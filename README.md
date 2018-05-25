
# Crypto Data

## Oracle SQL and PL/SQL solution to hide sensitive data

###    Why?
Some data could be so sensitive, than neither the system nor sys user can see them. But those guys have to see everything! 
Then how? I found a simple and easy way to manage these kind of data.

### How?
Follow this example to see the way of working.
Here is a table. The sensitive data is stored in encrypted column with its keys (the key name only!) but they are invisible (12c or higher)
The visible data is the decrypted but that is null if we do not have the right key value

    create table SECURE_TEST
    (  id                   number primary key,
       data_key             varchar2(100) invisible,
       encrypted_data       varchar2(100) invisible,
       decrypted_data       as ( DECRYPT_DATA( encrypted_data, data_key ) )    -- virtual column
    );

a trigger can handle the key and data storing behind automaticaly

    create or replace trigger TR_SECURE_TEST_BIUR 
        before insert or update on SECURE_TEST for each row
    begin
        :new.data_key       := PKG_CRYPTO.GET_KEY;   -- get the actual key value
        -- without key we can not store the encrypted data
        if :new.data_key is null then
            raise_application_error ( -20000, 'There is no active secure key to encrypt the data!' );    
        end if;
        :new.encrypted_data := ENCRYPT_DATA( :new.encrypted_data );  -- encrypt with the current key
    end;
    /

add some key and set the first one to active. That is important for the insert only we can use several keys in the same time for reading, but we can use exactly one for writing

    begin
        PKG_CRYPTO.ADD_KEY( 'key_1', 'djk43434sjkshsfksh'        );
        PKG_CRYPTO.ADD_KEY( 'key_2', 'djksjkshsrerraa2eererfksh' );
        PKG_CRYPTO.SET_KEY( 'key_1' ); 
    end;
    /

    insert into SECURE_TEST ( id, encrypted_data ) values ( 1, 12345 );
    commit;

because the select uses the stored key to decrypt

    select * from SECURE_TEST;

        ID DECRYPTED_DATA   
    ------ ---------------
         1 12345            

if we delete the key from the memory, 

    begin
        PKG_CRYPTO.DEL_KEY( 'key_1' );
    end;
    /

we can not see the data anymore:

    select * from SECURE_TEST;

        ID DECRYPTED_DATA   
    ------ ---------------
         1            

the whole picture is:
    select id, data_key, encrypted_data, decrypted_data  from SECURE_TEST;

     ID DATA_KEY   ENCRYPTED_DATA     DECRYPTED_DATA   
    --- ---------- ------------------ -----------------
      1 KEY_1     F5E548B37BEF26F4  

if we set a wrong key value for the key_1

    begin
        PKG_CRYPTO.ADD_KEY( 'key_1', 'djxxxxxxxxsh'        );
        PKG_CRYPTO.SET_KEY( 'key_1' );
    end;
    /

we still can not see the data

    select id, data_key, encrypted_data, decrypted_data  from SECURE_TEST;

     ID DATA_KEY   ENCRYPTED_DATA     DECRYPTED_DATA
    --- ---------- ------------------ -----------------
      1 KEY_1      F5E548B37BEF26F4 

but if we set the right key value for key_1

    begin
        PKG_CRYPTO.ADD_KEY( 'key_1', 'djk43434sjkshsfksh'        );
        PKG_CRYPTO.SET_KEY( 'key_1' );
    end;
    /
    
we can see it again

    select id, data_key, encrypted_data, decrypted_data  from SECURE_TEST;
     ID DATA_KEY   ENCRYPTED_DATA     DECRYPTED_DATA
    --- ---------- ------------------ -----------------
      1 KEY_1      F5E548B37BEF26F4   12345 


    select * from SECURE_TEST;
        ID DECRYPTED_DATA   
    ------ ---------------
         1 12345            

###    Objects
    
**PKG_CRYPTO** package manages the keys, and data decoding and encoding.

    PROCEDURE ADD_KEY( I_KEY_NAME   IN VARCHAR2, I_KEY_VALUE  IN VARCHAR2 )
        Adds or updates the key value of the specified key.

    PROCEDURE DEL_KEY( I_KEY_NAME IN VARCHAR2 )
        Removes the specified key from list of the active session keys

    PROCEDURE SET_KEY( I_KEY_NAME IN VARCHAR2 )
        For inserting/updating there must be at least one current key to encrypt data. We can set it by this proceudre.

    FUNCTION  GET_KEY      RETURN VARCHAR2
        Returns with the name of the current (encrypt) key.

    FUNCTION  ENCRYPT( I_VALUE     IN VARCHAR2 ) RETURN VARCHAR2
        Returns with the encrypted form of the specified value. Both the value and encrypted forms are strings. 
        The function uses the current key for encrypting.

    FUNCTION  DECRYPT( I_VALUE     IN VARCHAR2, I_KEY_NAME  IN VARCHAR2 ) RETURN VARCHAR2
        Returns with the decrypted form of the specified value. The function uses the specified key (name) for decrypting.
        Returns with null if the key name does not exsist in the list of set up keys, or in case of any other invalid situation.
        
    ENCRYPT_DATA and DECRYPT_DATA functions are only references to the ENCRYPT and DECRYPT functions in the PKG_CRYPTO package.

                     
## Licence
GPL
