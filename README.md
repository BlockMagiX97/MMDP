# MMDP
maximaly mininal dynamic protocol
(most work on compile time)
## FEATURES
- basic
- serialization 
- array support (only those defined in MMDP macros)
- custom type support (types defined elsewhere)
- essential structs and fields
- a way for program to check if field or struct is supported

## TODO
- add ajustable limits to memory alocations 

- add not-prefered fields (are sent only if client or server require them) (are only recomendation from the server)

- remove all memory leaks (should be done)
- refactor and improve the code

## Send fields conditionaly
only 2 types of fields can be sent conditionaly. Other types are always sent.
You can chose to not send only ARRAY or STRUCT_ARRAY.
You can achieve this by setting their DEPENDS_ON to field to 0.
unfortunetly this eliminates all fields that depend on the same DEPENDS_ON.

## Caveats and limitations
- Any struct_name cannot equal any other struct_name (including custom structs)
- Struct cannot have fields with same name
- You cannot have a struct_name + _ + fields_name that equals a different struct_name + _ + field_name
    - Example of violation:
            "struct_a" + "_" + "b_c" == "struct_a_b_c"
            "struct_a_b" + "_" + "c" == "struct_a_b_c"
- Packets can be only 2^32 bytes long
- You can only have 2^32 mmdp_structs
- You can only have 2^32 fields per mmdp_struct
- You can only have 2^32 mmdp_custom_structs

