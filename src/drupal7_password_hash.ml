let itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

(* _password_base64_encode *)
let base64_encode s =
  let get i =
    if i < String.length s
    then int_of_char s.[i]
    else 0 in
  let len = String.length s in
  let buf = Buffer.create ((1 + (len - 1) / 3) * 4) in
  let add_char v = Buffer.add_char buf itoa64.[v land 0x3f] in
  let rec loop i =
    if i >= len
    then ()
    else
      let v = get i lor (get (i+1) lsl 8) lor (get (i+2) lsl 16) in
      add_char v;
      add_char (v lsr 6);
      if i + 1 >= len then ()
      else begin
        add_char (v lsr 12);
        if i + 2 >= len then ()
        else begin
          add_char (v lsr 18);
          loop (i+3)
        end
      end
  in
  loop 0;
  Buffer.contents buf

let digest_of_string = function
  | "$S$" -> `SHA512
  | "$H$" | "$P$" -> `MD5
  | _ -> raise Not_found

(* 55 is including the 'settings' *)
let hash_length = 55 - 12

let verify password (encoded : string) =
  let password = Cstruct.of_string password in
  let digest = digest_of_string (String.sub encoded 0 3) in
  let module Digest = (val Mirage_crypto.Hash.module_of digest : Mirage_crypto.Hash.S) in
  let count =
    let count_log2 = String.index itoa64 encoded.[3] in
    1 lsl count_log2
  and salt = String.sub encoded 4 8 in
  let hash = ref (Digest.digest (Cstruct.append (Cstruct.of_string salt) password)) in
  for _ = 1 to count do
    hash := Digest.digest (Cstruct.append !hash password)
  done;
  let hash_encoded =
    let encoded = base64_encode (Cstruct.to_string !hash) in
    String.sub encoded 0 hash_length in
    hash_encoded = (String.sub encoded 12 hash_length)

let hash_with_salt password random_salt =
  let () = assert (String.length random_salt = 6) in
  let count_log2 = 15 in
  let salt = base64_encode random_salt in
  let settings = Printf.sprintf "$S$%c%s"
      itoa64.[count_log2]
      salt in
  let count = 1 lsl count_log2 in
  let hash = ref (Mirage_crypto.Hash.SHA512.digest (Cstruct.of_string (salt ^ password))) in
  for _ = 1 to count do
    hash := Mirage_crypto.Hash.SHA512.digest (Cstruct.append !hash (Cstruct.of_string password))
  done;
  settings ^ base64_encode (Cstruct.to_string !hash)
