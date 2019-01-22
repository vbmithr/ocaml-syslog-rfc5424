(*---------------------------------------------------------------------------
   Copyright (c) 2019 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

module R : Record.S

type tydef

val string : string Logs.Tag.def -> tydef
val bool : bool Logs.Tag.def -> tydef
val float : float Logs.Tag.def -> tydef
val i64 : int64 Logs.Tag.def -> tydef
val u64 : Uint64.t Logs.Tag.def -> tydef
val u : unit Logs.Tag.def -> tydef

val capnp_of_syslog :
  ?tydefs:tydef list -> Rfc5424.t -> R.Builder.Record.t
(** [capnp_of_syslog ?string ... t] is the flowgger capnp
    representation of a RFC5424 syslog entry. If optional tag
    definitions are provided, tags will be encoded with their native
    type in the capnp representation instead of being serialized in a
    string. *)

val syslog_of_capnp : R.Builder.Record.t -> Rfc5424.t

val pp :
  ?tydefs:tydef list ->
  compression:Capnp.Codecs.compression_t -> unit ->
  Format.formatter -> Rfc5424.t -> unit
(** [pp ... ppf t] formats [t] in [capnp] format. *)

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
