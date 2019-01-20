(*---------------------------------------------------------------------------
   Copyright (c) 2019 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

module R = Record.Make(Capnp.BytesMessage)
open R.Builder

let iter_non_empty_string ~f = function
  | "" -> ()
  | s -> f s

type _ deflist =
  | String : string Logs.Tag.def list -> string deflist
  | Bool : bool Logs.Tag.def list -> bool deflist
  | Float : float Logs.Tag.def list -> float deflist
  | I64 : int64 Logs.Tag.def list -> int64 deflist
  | U64 : Uint64.t Logs.Tag.def list -> Uint64.t deflist
  | U : unit Logs.Tag.def list -> unit deflist

let get_list :
  type a. a deflist -> a Logs.Tag.def list = function
  | String l -> l
  | Bool l -> l
  | Float l -> l
  | I64 l -> l
  | U64 l -> l
  | U l -> l

type defs = {
  s : string deflist ;
  b : bool deflist ;
  f : float deflist ;
  i64 : Int64.t deflist ;
  u64 : Uint64.t deflist ;
  u : unit deflist ;
}

let rfc5424_section = "rfc5424_section"

let build_pairs ~defs section tags =
  let init_key d =
    let p = Pair.init_root () in
    Pair.key_set p (Logs.Tag.name d) ;
    let v = Pair.value_init p in
    p, v in
  let set_value (type p) (l : p deflist) v (tagv : p) =
    match l with
    | String _ -> Pair.Value.string_set v tagv
    | Bool _ -> Pair.Value.bool_set v tagv
    | Float _ -> Pair.Value.f64_set v tagv
    | I64 _ -> Pair.Value.i64_set v tagv
    | U64 _ -> Pair.Value.u64_set v tagv
    | U _ -> Pair.Value.null_set v in
  let build_pairs tags pairs l =
    List.fold_left begin fun ((tags, pairs) as a) d ->
      match Logs.Tag.find d tags with
      | None -> a
      | Some tagv ->
        let p, v = init_key d in
        set_value l v tagv ;
        Logs.Tag.rem d tags, p :: pairs
    end (tags, pairs) (get_list l) in
  let section_pair =
    let p = Pair.init_root () in
    Pair.key_set p rfc5424_section ;
    let v = Pair.value_init p in
    Pair.Value.string_set v section ;
    p in
  let tags, pairs = build_pairs tags [section_pair] defs.s in
  let tags, pairs = build_pairs tags pairs defs.b in
  let tags, pairs = build_pairs tags pairs defs.f in
  let tags, pairs = build_pairs tags pairs defs.i64 in
  let tags, pairs = build_pairs tags pairs defs.u64 in
  let tags, pairs = build_pairs tags pairs defs.u in
  Logs.Tag.fold begin fun (Logs.Tag.V (d, t)) pairs ->
    let p = Pair.init_root () in
    let v = Pair.value_init p in
    Pair.key_set p (Logs.Tag.name d) ;
    Pair.Value.string_set v (Format.asprintf "%a" (Logs.Tag.printer d) t) ;
    p :: pairs
  end tags pairs

let capnp_of_syslog
    ?(string=[]) ?(bool=[]) ?(float=[])
    ?(i64=[]) ?(u64=[]) ?(u=[])
    ({ header = { facility; severity; version = _; ts;
                  hostname; app_name; procid; msgid }; tags; msg } : Rfc5424.t) =
  let defs = {
    s = String string ;
    b = Bool bool ;
    f = Float float ;
    i64 = I64 i64 ;
    u64 = U64 u64 ;
    u = U u ;
  } in
  let r = Record.init_root () in
  Record.facility_set_exn r (Syslog_message.int_of_facility facility) ;
  Record.severity_set_exn r (Syslog_message.int_of_severity severity) ;
  Record.ts_set r (Ptime.to_float_s ts) ;
  iter_non_empty_string hostname ~f:(Record.hostname_set r) ;
  iter_non_empty_string app_name ~f:(Record.appname_set r) ;
  iter_non_empty_string procid ~f:(Record.procid_set r) ;
  iter_non_empty_string msgid ~f:(Record.msgid_set r) ;
  iter_non_empty_string msg ~f:(Record.msg_set r) ; (* OVH needs this *)
  iter_non_empty_string msg ~f:(Record.full_msg_set r) ;
  let pairs = List.fold_left begin fun a (section, tags) ->
      List.rev_append (build_pairs section ~defs tags) a
    end [] tags in
  let _ = Record.pairs_set_list r pairs in
  r

let pp_print_int64 ppf i = Format.fprintf ppf "%Ld" i

let string_option_of_string = function
  | "" -> None
  | s -> Some s

module SM = Map.Make(String)

let syslog_of_capnp r =
  let facility =
    Syslog_message.facility_of_int (Record.facility_get r) in
  let severity =
    Syslog_message.severity_of_int (Record.severity_get r) in
  let hostname = string_option_of_string @@ Record.hostname_get r in
  let app_name = string_option_of_string @@ Record.appname_get r in
  let procid = string_option_of_string @@ Record.procid_get r in
  let msgid = string_option_of_string @@ Record.msgid_get r in
  let msg = string_option_of_string @@ Record.full_msg_get r in
  let ts =
    match Ptime.of_float_s (Record.ts_get r) with
    | None -> Ptime.epoch
    | Some ts -> ts in
  let _, tags =
    List.fold_left begin fun (c, m) p ->
      let k = Pair.key_get p in
      let v = Pair.value_get p in
      let update d v m =
        SM.update c begin function
          | None -> Some (Logs.Tag.(add d v empty))
          | Some s -> Some (Logs.Tag.add d v s)
        end m in
      match Pair.Value.get v with
      | String s when k = rfc5424_section -> s, m
      | String s -> c, update (Logs.Tag.def k Format.pp_print_string) s m
      | Bool b -> c, update (Logs.Tag.def k Format.pp_print_bool) b m
      | F64 f -> c, update (Logs.Tag.def k Format.pp_print_float) f m
      | I64 i -> c, update (Logs.Tag.def k pp_print_int64) i m
      | U64 i -> c, update (Logs.Tag.def k Uint64.printer) i m
      | Null -> c, update (Logs.Tag.def k Format.pp_print_space) () m
      | Undefined _ -> c, m
    end ("", SM.empty) (Record.pairs_get_list r) in
  let tags = SM.bindings tags in
  Rfc5424.create
    ?facility ?severity ?hostname
    ?app_name ?procid ?msgid ?msg ~tags ~ts ()

let pp ?string ?float ?i64 ?u64 ?u ~compression () ppf t =
  let r = capnp_of_syslog ?string ?float ?i64 ?u64 ?u t in
  let m = R.Builder.Record.to_message r in
  Format.pp_print_string ppf (Capnp.Codecs.serialize ~compression m)

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
