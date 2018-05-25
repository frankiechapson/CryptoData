
CREATE OR REPLACE PACKAGE PKG_CRYPTO IS

/* *************************************************************
    History of changes
    yyyy.mm.dd | Version | Author         | Changes
    -----------+---------+----------------+-------------------------
    2017.01.16 |  1.0    | Ferenc Toth    | Created 

************************************************************* */

    type T_KEYS         is table of varchar2( 100 ) index by varchar2( 100 ); 

    -------------------------------------------------------------------------------------------------
    PROCEDURE ADD_KEY( I_KEY_NAME   IN VARCHAR2
                     , I_KEY_VALUE  IN VARCHAR2 
                     );
    -------------------------------------------------------------------------------------------------
    PROCEDURE DEL_KEY( I_KEY_NAME IN VARCHAR2 );
    -------------------------------------------------------------------------------------------------
    PROCEDURE SET_KEY( I_KEY_NAME IN VARCHAR2 );
    -------------------------------------------------------------------------------------------------
    FUNCTION  GET_KEY      RETURN VARCHAR2;
    -------------------------------------------------------------------------------------------------
    FUNCTION  ENCRYPT( I_VALUE     IN VARCHAR2 
                     ) RETURN VARCHAR2;
    -------------------------------------------------------------------------------------------------
    FUNCTION  DECRYPT( I_VALUE     IN VARCHAR2
                     , I_KEY_NAME  IN VARCHAR2 
                     ) RETURN VARCHAR2;
    -------------------------------------------------------------------------------------------------

END;
/

/*============================================================================================*/

CREATE OR REPLACE PACKAGE BODY PKG_CRYPTO IS

/* *************************************************************
    History of changes
    yyyy.mm.dd | Version | Author         | Changes
    -----------+---------+----------------+-------------------------
    2017.01.16 |  1.0    | Ferenc Toth    | Created 

************************************************************* */

    G_ENC_TYPE          PLS_INTEGER:= sys.dbms_crypto.encrypt_3des + sys.dbms_crypto.chain_cbc + sys.dbms_crypto.pad_pkcs5;
    G_KEYS              T_KEYS;
    DC_KEY_NAME         varchar2( 100 );


    -------------------------------------------------------------------------------------------------
    PROCEDURE ADD_KEY( I_KEY_NAME  IN VARCHAR2
                     , I_KEY_VALUE IN VARCHAR2 
                     ) IS
    -------------------------------------------------------------------------------------------------
    begin
        G_KEYS ( upper( I_KEY_NAME ) ) := I_KEY_VALUE;
    end;


    -------------------------------------------------------------------------------------------------
    PROCEDURE DEL_KEY( I_KEY_NAME IN VARCHAR2 ) IS
    -------------------------------------------------------------------------------------------------
    BEGIN
        G_KEYS.DELETE ( upper( I_KEY_NAME ) );
        IF I_KEY_NAME = DC_KEY_NAME THEN
            DC_KEY_NAME := NULL;
        END IF;
    END;


    -------------------------------------------------------------------------------------------------
    PROCEDURE SET_KEY( I_KEY_NAME IN VARCHAR2 ) IS
    -------------------------------------------------------------------------------------------------
    BEGIN
        IF G_KEYS.EXISTS ( upper( I_KEY_NAME ) ) THEN 
            DC_KEY_NAME :=  upper( I_KEY_NAME );
        ELSE
            DC_KEY_NAME := NULL;
        END IF;
    END;


    -------------------------------------------------------------------------------------------------
    FUNCTION GET_KEY RETURN VARCHAR2 IS
    -------------------------------------------------------------------------------------------------
    BEGIN
        RETURN DC_KEY_NAME;
    END;



    -------------------------------------------------------------------------------------------------
    FUNCTION ENCRYPT( I_VALUE IN VARCHAR2 ) RETURN VARCHAR2 IS
    -------------------------------------------------------------------------------------------------
        V_IN_KEY    raw( 2048 );
        V_IN_DATA   raw( 2048 );
        V_DATA_ENC  raw( 2048 );
    BEGIN
        V_IN_KEY   := sys.utl_i18n.string_to_raw( substr( rpad( G_KEYS ( DC_KEY_NAME ), 32, 'X' ), 1, 32 ), 'AL32UTF8' );
        V_IN_DATA  := sys.utl_i18n.string_to_raw( I_VALUE, 'AL32UTF8' );
        V_DATA_ENC := sys.dbms_crypto.encrypt( src => V_IN_DATA, typ => G_ENC_TYPE, key => V_IN_KEY );
        RETURN V_DATA_ENC;
    EXCEPTION
        WHEN OTHERS THEN RETURN NULL;
    END;


    -------------------------------------------------------------------------------------------------
    FUNCTION DECRYPT( I_VALUE     IN VARCHAR2
                    , I_KEY_NAME  IN VARCHAR2 ) RETURN VARCHAR2 IS
    -------------------------------------------------------------------------------------------------
        V_IN_KEY    raw( 2048 );
        V_IN_DATA   raw( 2048 );
        V_DATA_DEC  raw( 2048 );
    BEGIN
        IF I_KEY_NAME IS NULL THEN
            RETURN I_VALUE;
        END IF;
        V_IN_KEY   := sys.utl_i18n.string_to_raw( substr( rpad( G_KEYS ( upper( I_KEY_NAME ) ), 32, 'X' ), 1, 32 ), 'AL32UTF8' );
        V_IN_DATA  := I_VALUE;
        V_DATA_DEC := sys.dbms_crypto.decrypt( src => V_IN_DATA, typ => G_ENC_TYPE, key => V_IN_KEY );
        RETURN utl_i18n.raw_to_char( V_DATA_DEC, 'AL32UTF8');
    EXCEPTION
        WHEN OTHERS THEN RETURN NULL;
    END;

END;
/


CREATE OR REPLACE FUNCTION ENCRYPT_DATA( I_VALUE IN VARCHAR2 ) RETURN VARCHAR2 DETERMINISTIC IS
BEGIN
    RETURN PKG_CRYPTO.ENCRYPT( I_VALUE );
END;
/

CREATE OR REPLACE FUNCTION DECRYPT_DATA( I_VALUE IN VARCHAR2, I_KEY_NAME  IN VARCHAR2 ) RETURN VARCHAR2 DETERMINISTIC IS
BEGIN
    RETURN PKG_CRYPTO.DECRYPT( I_VALUE, I_KEY_NAME );
END;
/



/*************************************/
Prompt   G R A S Y N 
/*************************************/

/*============================================================================================*/
CREATE OR REPLACE PUBLIC SYNONYM ENCRYPT_DATA FOR ENCRYPT_DATA;
CREATE OR REPLACE PUBLIC SYNONYM DECRYPT_DATA FOR DECRYPT_DATA;
/*============================================================================================*/

/*============================================================================================*/
GRANT EXECUTE ON ENCRYPT_DATA TO PUBLIC;
GRANT EXECUTE ON DECRYPT_DATA TO PUBLIC;
/*============================================================================================*/


