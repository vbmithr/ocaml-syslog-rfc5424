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

val create :
  ?facility:Syslog_message.facility ->
  ?severity:Syslog_message.severity ->
  ?hostname:string ->
  ?app_name:string ->
  ?procid:string ->
  ?msgid:string ->
  ?tags:structured_data ->
  ts:Ptime.t -> unit -> ('a, Format.formatter, unit, t) format4 -> 'a

val equal : t -> t -> bool
val pp : Format.formatter -> t -> unit
val to_string : t -> string
val show : t -> string
val of_string : string -> (t, t Tyre.error) result

val severity_of_level : Logs.level -> Syslog_message.severity

(**/**)

val equal_structured_data :
  structured_data -> structured_data -> bool
val pp_print_structured_data :
  Format.formatter -> structured_data -> unit
val sd_name : string Tyre.t
val structured_data : structured_data Tyre.t

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
