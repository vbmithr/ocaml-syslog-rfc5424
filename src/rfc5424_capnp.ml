(*---------------------------------------------------------------------------
   Copyright (c) 2019 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

module R = Record.Make(Capnp.BytesMessage)

module Option = struct
  let iter ~f = function
    | None -> ()
    | Some v -> f v
end

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

let build_pairs ?section ?(prefix="_") ~defs tags =
  let open R.Builder in
  let prefixed_name d =
    match section with
    | None -> Logs.Tag.name d
    | Some s -> s ^ prefix ^ Logs.Tag.name d in
  let init_key d =
    let p = Pair.init_root () in
    Pair.key_set p (prefixed_name d) ;
    let v = Pair.value_init p in
    p, v in
  let set_value (type p) (l : p deflist) v (tagv : p) =
    match l with
    | String _ -> Pair.Value.string_set v tagv
    | _ -> failwith "" in
  let build_pairs tags pairs l =
    List.fold_left begin fun ((tags, pairs) as a) d ->
      match Logs.Tag.find d tags with
      | None -> a
      | Some tagv ->
        let p, v = init_key d in
        set_value l v tagv ;
        Logs.Tag.rem d tags, p :: pairs
    end (tags, pairs) (get_list l) in
  let tags, pairs = build_pairs tags [] defs.s in
  let tags, pairs = build_pairs tags pairs defs.b in
  let tags, pairs = build_pairs tags pairs defs.f in
  let tags, pairs = build_pairs tags pairs defs.i64 in
  let tags, pairs = build_pairs tags pairs defs.u64 in
  let tags, pairs = build_pairs tags pairs defs.u in
  Logs.Tag.fold begin fun (Logs.Tag.V (d, t)) pairs ->
    let p = Pair.init_root () in
    let v = Pair.value_init p in
    Pair.key_set p (prefixed_name d) ;
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
  let open R.Builder in
  let r = Record.init_root () in
  Record.facility_set_exn r (Syslog_message.int_of_facility facility) ;
  Record.severity_set_exn r (Syslog_message.int_of_severity severity) ;
  Record.ts_set r (Ptime.to_float_s ts) ;
  Option.iter hostname ~f:(Record.hostname_set r) ;
  Option.iter app_name ~f:(Record.appname_set r) ;
  Option.iter procid ~f:(Record.procid_set r) ;
  Option.iter msgid ~f:(Record.msgid_set r) ;
  let pairs = List.fold_left begin fun a (section, tags) ->
      List.rev_append (build_pairs ~section ~defs tags) a
    end [] tags in
  let _ = Record.pairs_set_list r pairs in
  Option.iter msg ~f:(Record.full_msg_set r) ;
  r

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
