val verify : string -> string -> bool
(** [verify password hash] returns [true] if [password] hashes to the same
 * hash as [hash] *)

val hash_with_salt : string -> string -> string
(** [hash_with_salt password random_salt] hashes [password] with a salt
 * derived from [random_salt].
 * [random_salt] must be exactly 6 random bytes. *)
