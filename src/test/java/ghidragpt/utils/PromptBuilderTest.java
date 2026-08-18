package ghidragpt.utils;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PromptBuilderTest {

    @Test
    void addSection_appendsTitleAndContent() {
        PromptBuilder b = new PromptBuilder();
        String out = b.addSection("Current function", "FUN_1234").build();
        assertEquals("Current function:\nFUN_1234\n\n", out);
    }

    @Test
    void builderChaining_isFluent() {
        PromptBuilder b = new PromptBuilder();
        assertSame(b, b.addSection("a", "1"));
        assertSame(b, b.addInstructions("i"));
        assertSame(b, b.addExamples("e"));
        assertSame(b, b.addNotes("n"));
    }

    @Test
    void addInstructions_addsStandardLabel() {
        String out = new PromptBuilder().addInstructions("focus on X").build();
        assertEquals("Analysis Instructions:\nfocus on X\n\n", out);
    }

    @Test
    void addExamples_addsStandardLabel() {
        String out = new PromptBuilder().addExamples("example json").build();
        assertEquals("Examples:\nexample json\n\n", out);
    }

    @Test
    void addNotes_addsStandardLabel() {
        String out = new PromptBuilder().addNotes("note text").build();
        assertEquals("Notes:\nnote text\n", out);
    }

    @Test
    void multipleSections_preserveOrder() {
        String out = new PromptBuilder()
            .addSection("First", "f1")
            .addSection("Second", "s2")
            .build();
        assertTrue(out.indexOf("First:") < out.indexOf("Second:"));
    }

    @Test
    void createFunctionAnalysisPrompt_containsNameAndCode() {
        String prompt = PromptBuilder.createFunctionAnalysisPrompt("FUN_00400000",
            "char *x;\nreturn x;").build();
        assertTrue(prompt.contains("Current function:\nFUN_00400000"));
        assertTrue(prompt.contains("Decompiled code:\nchar *x;\nreturn x;"));
    }
}
