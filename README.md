# MMDP
maximaly mininal dynamic protocol
(most work on compile time)
## FEATURES
- basic
- serialization 
- array support (only those defined in MMDP macros)
- custom type support (types defined elsewhere)
- essential structs and fields

## TODO
- add a way for program to check if field or struct is supported

- add ajustable limits to memory alocations 

- add not-prefered fields (are sent only if client or server require them) (are only recomendation from the server)

- remove all memory leaks (should be done)
- refactor and improve the code

## Send fields conditionaly
only 2 types of fields can be sent conditionaly. Other types are always sent.
You can chose to not send only ARRAY or STRUCT_ARRAY.
You can achieve this by setting their DEPENDS_ON to field to 0.
unfortunetly this eliminates all fields that depend on the same DEPENDS_ON.


