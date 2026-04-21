package com.godaddy.ans.sdk.transparency.scitt;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

/**
 * Shared CBOR field extraction helpers used by COSE and status token parsers.
 *
 * <p>These methods provide consistent extraction and validation of typed values
 * from CBOR maps and arrays, with clear error messages on type mismatches.</p>
 */
final class CborExtractors {

    private CborExtractors() {
    }

    /**
     * Extracts a required byte string from a CBOR array.
     *
     * @param array the CBOR array
     * @param index the array index
     * @param name descriptive name for error messages
     * @return the byte string value
     * @throws ScittParseException if the element is missing or not a byte string
     */
    static byte[] extractByteString(CBORObject array, int index, String name)
            throws ScittParseException {
        CBORObject element = array.get(index);
        if (element == null || element.getType() != CBORType.ByteString) {
            throw new ScittParseException(name + " must be a byte string");
        }
        return element.GetByteString();
    }

    /**
     * Extracts an optional byte string from a CBOR array.
     *
     * @param array the CBOR array
     * @param index the array index
     * @param name descriptive name for error messages
     * @return the byte string value, or null if absent
     * @throws ScittParseException if present but not a byte string
     */
    static byte[] extractOptionalByteString(CBORObject array, int index, String name)
            throws ScittParseException {
        CBORObject element = array.get(index);
        if (element == null || element.isNull()) {
            return null;
        }
        if (element.getType() != CBORType.ByteString) {
            throw new ScittParseException(name + " must be a byte string or null");
        }
        return element.GetByteString();
    }

    /**
     * Extracts a required string from a CBOR map by integer key.
     *
     * @param map the CBOR map
     * @param key the integer key
     * @return the string value
     * @throws ScittParseException if the field is missing or not a string
     */
    static String extractRequiredString(CBORObject map, int key) throws ScittParseException {
        CBORObject value = map.get(CBORObject.FromObject(key));
        if (value == null || value.isNull()) {
            throw new ScittParseException("Missing required field at key " + key);
        }
        if (value.getType() != CBORType.TextString) {
            throw new ScittParseException("Field at key " + key + " must be a string");
        }
        return value.AsString();
    }

    /**
     * Extracts an optional string from a CBOR map by integer key.
     *
     * @param map the CBOR map
     * @param label the integer key
     * @return the string value, or null if absent or not a string
     */
    static String extractOptionalString(CBORObject map, int label) {
        CBORObject value = map.get(CBORObject.FromObject(label));
        if (value != null && value.getType() == CBORType.TextString) {
            return value.AsString();
        }
        return null;
    }

    /**
     * Extracts an optional long from a CBOR map by integer key.
     *
     * @param map the CBOR map
     * @param label the integer key
     * @return the long value, or null if absent or not a number
     */
    static Long extractOptionalLong(CBORObject map, int label) {
        CBORObject value = map.get(CBORObject.FromObject(label));
        if (value != null && value.isNumber()) {
            return value.AsInt64();
        }
        return null;
    }
}
