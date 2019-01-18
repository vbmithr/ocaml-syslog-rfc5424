(*---------------------------------------------------------------------------
   Copyright (c) 2019 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

type t = {
  header : header ;
  tags : structured_data ;
  msg : string option ;
}

and structured_data =
  (string * Logs.Tag.set) list

and header = {
  facility : Syslog_message.facility ;
  severity : Syslog_message.severity ;
  version : int ;
  ts : Ptime.t ;
  hostname : string option ;
  app_name : string option ;
  procid : string option ;
  msgid : string option ;
}

let equal_structured_data =
  let module SM = Map.Make(String) in
  let load m =
    List.fold_left (fun a (k, v) -> SM.add k v a) SM.empty m in
  fun tags tags' ->
    let tags = load tags in
    let tags' = load tags' in
    SM.equal begin fun a b ->
      String.equal
        (Format.asprintf "%a" Logs.Tag.pp_set a)
        (Format.asprintf "%a" Logs.Tag.pp_set b)
    end tags tags'

let equal t t' =
  t.header = t'.header &&
  t.msg = t'.msg &&
  equal_structured_data t.tags t'.tags

let pp_print_nil_option pp ppf = function
  | None -> Format.pp_print_char ppf '-'
  | Some v -> Format.fprintf ppf "%a" pp v

let pp_print_header ppf { facility ; severity ; version ; ts ;
                    hostname ; app_name ; procid ; msgid } =
  Format.fprintf ppf "<%d>%d %a %a %a %a %a"
    Syslog_message.(int_of_facility facility * 8 + int_of_severity severity)
    version
    (Ptime.pp_rfc3339 ~frac_s:6 ~tz_offset_s:0 ()) ts
    (pp_print_nil_option Format.pp_print_string) hostname
    (pp_print_nil_option Format.pp_print_string) app_name
    (pp_print_nil_option Format.pp_print_string) procid
    (pp_print_nil_option Format.pp_print_string) msgid

let pp_print_kv ppf (Logs.Tag.V (d, v)) =
  Format.fprintf ppf "%s=\"%a\""
    (Logs.Tag.name d) (Logs.Tag.printer d) v

let pp_print_tagset ?pp_space pp ppf set =
  Logs.Tag.fold begin fun t a ->
    begin match a, pp_space with
    | true, Some pp -> Format.fprintf ppf "%a" pp ()
    | _ -> ()
    end ;
    Format.fprintf ppf "%a" pp t ;
    true
  end set false |> fun _ -> ()

let pp_print_group ppf (name, set) =
  let pp_space ppf () = Format.pp_print_char ppf ' ' in
  Format.fprintf ppf "[%s %a]"
    name (pp_print_tagset ~pp_space pp_print_kv) set

let pp_print_structured_data ppf = function
  | [] -> Format.pp_print_char ppf '-'
  | tags ->
    Format.pp_print_list
      ~pp_sep:(fun _ppf () -> ()) pp_print_group ppf tags

let pp ppf { header ; tags ; msg } =
  match msg with
  | None ->
    Format.fprintf ppf "%a %a"
      pp_print_header header
      pp_print_structured_data tags
  | Some msg ->
    Format.fprintf ppf "%a %a BOM%s"
      pp_print_header header
      pp_print_structured_data tags msg

let to_string t =
  Format.asprintf "%a" pp t

let show = to_string

let pri =
  let open Syslog_message in
  let parse_pri pri =
    match facility_of_int (pri / 8),
          severity_of_int (pri mod 8) with
    | Some f, Some s -> Some (f, s)
    | _ -> None in
  let parse_pri_exn pri =
    match parse_pri pri with
    | Some v -> v
    | None -> invalid_arg "parse_pri" in
  let open Tyre in
  conv
    parse_pri_exn
    (fun (f, s) -> int_of_facility f * 8 + int_of_severity s)
    Tyre.(char '<' *> int <* char '>')

let ts =
  let open Rresult in
  let open Tyre in
  conv begin fun s ->
      match Ptime.of_rfc3339 s with
        | Error (`RFC3339 _) as e ->
          R.error_msg_to_invalid_arg (Ptime.rfc3339_error_to_msg e)
        | Ok (t, _, _) -> t
  end
    (fun s -> Ptime.to_rfc3339 s)
    (pcre "[0-9+-\\.:TZtz]+")

let stropt =
  let open Tyre in
  conv
    (function `Right s -> Some s | `Left () -> None)
    (function Some s -> `Right s | None -> `Left ())
    (char '-' <|> pcre "[[:graph:]]+")

let sd_name = Tyre.pcre "[^ =\\]\"]+"
let param_value = Tyre.pcre "[^\"\\\\\\]]*"

let sd_param =
  let open Tyre in
  sd_name <* char '=' <&> char '"' *> param_value <* char '"'

let tags_of_seq =
  let defs_table = Hashtbl.create 13 in
  fun s ->
    let open Logs.Tag in
    Seq.fold_left begin fun a (k, v) ->
      match Hashtbl.find_opt defs_table k with
      | Some d -> add d v a
      | None ->
        let d = def k Format.pp_print_string in
        Hashtbl.add defs_table k d ;
        add d v a
    end Logs.Tag.empty s

let seq_of_tags s =
  let open Logs.Tag in
  fold begin fun (V (def, v)) a ->
    fun () ->
      Seq.Cons ((name def, Format.asprintf "%a" (printer def) v), a)
  end s Seq.empty

let sd_element =
  let open Tyre in
  conv
    (fun (name, tags) -> name, tags_of_seq tags)
    (fun (name, tags) -> (name, seq_of_tags tags))
    (char '[' *> sd_name <&> rep (blanks *> sd_param) <* char ']')

let structured_data =
  let open Tyre in
  conv
    begin function
      | `Left () -> []
      | `Right (a, s) ->
        List.rev (Seq.fold_left (fun a s -> s :: a) [a] s)
    end
    begin function
      | [] -> `Left ()
      | h :: t -> `Right (h, List.to_seq t)
    end
    (char '-' <|> rep1 sd_element)

let msg =
  let open Tyre in
  conv
    (function `Left msg -> msg | `Right msg -> msg)
    (fun s ->
       let len = String.length s in
       if len > 2 || String.sub s 0 3 = "BOM" then
         `Left (String.sub s 3 (len - 3))
       else `Right s)
    (str "BOM" *> pcre ".*" <|> pcre "[^B].*")

let of_tyre (((((((((facility, severity), version), ts),
                  hostname), app_name), procid), msgid), tags), msg) =
  let header = {
    facility ; severity ; version ; ts ;
    hostname ; app_name ; procid ; msgid } in
  { header ; tags ; msg }

let to_tyre { header = {
    facility ; severity ; version ; ts ;
    hostname ; app_name ; procid ; msgid } ; tags ; msg } =
  (((((((((facility, severity), version), ts),
        hostname), app_name), procid), msgid), tags), msg)

let re =
  let open Tyre in
  conv of_tyre to_tyre
    (whole_string (pri <&>
                   int <&>
                   blanks *> ts <&>
                   blanks *> stropt <&> (* hostname *)
                   blanks *> stropt <&> (* app_name *)
                   blanks *> stropt <&> (* procid *)
                   blanks *> stropt <&> (* msgid *)
                   blanks *> structured_data <&>
                   opt (blanks *> msg)))
  |> compile

let of_string = Tyre.exec re

(*---------------------------------------------------------------------------
   Copyright (c) 2019 Vincent Bernardoff

   Permission to use, copy, modify, and/or distribute this software for any
   purpose with or without fee is hereby granted, provided that the above
   copyright notice and this permission notice appear in all copies.

   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
  ---------------------------------------------------------------------------*)
