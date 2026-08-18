package ghidragpt.utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ResponseParserTest {

    @Test
    void extractFunctionCode_fromJsonCodeKey() {
        String response = "{\"code\": \"void f() { return; }\", \"explanation\": \"x\"}";
        assertEquals("void f() { return; }", ResponseParser.extractFunctionCode(response));
    }

    @Test
    void extractFunctionCode_fromJsonFunctionKey() {
        String response = "{\"function\": \"void f(a int) { return a; }\"}";
        assertEquals("void f(a int) { return a; }", ResponseParser.extractFunctionCode(response));
    }

    @Test
    void extractFunctionCode_fromJsonRewrittenCodeKey() {
        String response = "{\"rewritten_code\": \"void f() { return; }\"}";
        assertEquals("void f() { return; }", ResponseParser.extractFunctionCode(response));
    }

    @Test
    void extractFunctionCode_fromFencedCodeBlockWhenValid() {
        String code = "public static int add(int a, int b) { return a + b; }";
        String response = "Here is the code:\n```c\n" + code + "\n```\nDone.";
        assertEquals(code, ResponseParser.extractFunctionCode(response));
    }

    @Test
    void extractFunctionCode_fencedBlockNotValidFallsThrough() {
        // no modifier keyword -> not valid function code per heuristic
        String response = "```\nint x = compute();\n```\n";
        assertNull(ResponseParser.extractFunctionCode(response));
    }

    @Test
    void extractFunctionCode_rawCodeFallback() {
        String raw = "public static void main(String[] args) { System.out.println(1); }";
        assertEquals(raw, ResponseParser.extractFunctionCode(raw));
    }

    @Test
    void extractFunctionCode_nullAndEmpty() {
        assertNull(ResponseParser.extractFunctionCode(null));
        assertNull(ResponseParser.extractFunctionCode("   "));
    }

    @Test
    void extractFunctionCode_nonCodeTextReturnsNull() {
        // no parens/braces -> not valid function code
        assertNull(ResponseParser.extractFunctionCode("just plain text, no code markers at all"));
    }

    @Test
    void extractExplanation_jsonExplanationKey() {
        assertEquals("explanation text",
            ResponseParser.extractExplanation("{\"explanation\": \"explanation text\"}"));
    }

    @Test
    void extractExplanation_jsonReasoningKey() {
        assertEquals("reasoning text",
            ResponseParser.extractExplanation("{\"reasoning\": \"reasoning text\"}"));
    }

    @Test
    void extractExplanation_textBeforeCodeBlock() {
        String response = "This function computes a checksum.\n```c\nvoid f() {}\n```";
        assertEquals("This function computes a checksum.", ResponseParser.extractExplanation(response));
    }

    @Test
    void extractExplanation_defaultFallback() {
        assertEquals("Function rewritten by model analysis", ResponseParser.extractExplanation("no markers here"));
    }

    @Test
    void extractExplanation_null() {
        assertEquals("", ResponseParser.extractExplanation(null));
    }

    @Test
    void isSuccessfulResponse_matrix() {
        assertEquals(false, ResponseParser.isSuccessfulResponse(null));
        assertEquals(false, ResponseParser.isSuccessfulResponse("an error occurred"));
        assertEquals(false, ResponseParser.isSuccessfulResponse("failed to process"));
        assertEquals(false, ResponseParser.isSuccessfulResponse("I am unable to do this"));
        assertEquals(true, ResponseParser.isSuccessfulResponse("Here is the code: ```c\nvoid f() {}\n```"));
        assertEquals(true, ResponseParser.isSuccessfulResponse("The function was rewritten"));
    }
}
