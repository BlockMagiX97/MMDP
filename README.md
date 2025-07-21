# MMDP
maximaly mininal dynamic protocol
(most work on compile time)
## FEATURES
- basic
- serialization 
- array support (only those defined in MMDP macros)
- custom type support (types defined elsewhere)

## TODO
- add ajustable limit to ALL size fields 

- add checks for essentiality
- add not-prefered fields (are sent only if client or server require them)
- add one-of-two fields (only one of the fields is required (useful for compatibility layers))
- add check for support for fields and structs

- remove all memory leaks (should be done)
## Send fields conditionaly
only 2 types of fields can be sent conditionaly. Other types are always sent.
You can chose to not send only ARRAY or STRUCT_ARRAY.
You can achieve this by setting their DEPENDS_ON to field to 0.
unfortunetly this eliminates all fields that depend on the same DEPENDS_ON.


