package ghidragpt.ui;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
// import docking.action.ToolBarData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidragpt.GhidraGPTPlugin;
import ghidragpt.service.CodeAnalysis;
// import resources.Icons;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/**
 * Main UI provider for the GhidraGPT plugin
 */
public class Provider extends ComponentProvider {

    private final GhidraGPTPlugin plugin;
    private final JPanel mainPanel;
    private final ConfigurationPanel configPanel;
    private final Console console;
    private final JTabbedPane tabbedPane;
    private CodeAnalysis analysisService;
    private Program currentProgram;

    public Provider(GhidraGPTPlugin plugin, String name) {
        super(plugin.getTool(), name, name);
        this.plugin = plugin;

        // Configure docking properties
        setDefaultWindowPosition(WindowPosition.BOTTOM);
        setTransient();

        // Initialize UI components
        mainPanel = new JPanel(new BorderLayout());
        configPanel = new ConfigurationPanel(plugin.getGPTService());
        console = new Console();

        // Create tabbed pane
        tabbedPane = new JTabbedPane();

        // Configuration tab - added directly (ConfigurationPanel has its own internal scroll)
        tabbedPane.addTab("Configuration", configPanel);
        tabbedPane.addTab("Console", console);

        mainPanel.add(tabbedPane, BorderLayout.CENTER);

        setVisible(true);
        createActions();
    }

    /**
     * Shows the configuration panel and brings the provider to front
     */
    public void showConfigurationTab() {
        tabbedPane.setSelectedIndex(0); // Configuration tab
        toFront();
    }

    /**
     * Switches to the console tab to show results
     */
    private void switchToConsoleTab() {
        tabbedPane.setSelectedIndex(1); // Console tab
        toFront();
    }

    private JPanel createButtonPanel() {
        // Return empty panel - buttons removed from configuration page
        return new JPanel();
    }

    private void createActions() {
        // Main context menu actions for GPT analysis
        createEnhanceFunctionAction();
        createExplainAction();
        createVulnerabilityAction();
        createResetLocalNamesAction();
        createShowConfigAction();
        createShowConsoleAction();
        createShowDataTypesAction();
        createSaveConfigAction();
    }

    private void createShowConfigAction() {
        DockingAction action = new DockingAction("GhidraGPT Configuration", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                setVisible(true);
                tabbedPane.setSelectedIndex(0);
                toFront();
            }
        };
        action.setKeyBindingData(new KeyBindingData(
            KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_F2, 0)));
        action.setDescription("Show GhidraGPT Configuration panel");
        plugin.getTool().addAction(action);
    }

    private void createSaveConfigAction() {
        DockingAction action = new DockingAction("Save GhidraGPT Config", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                if (isVisible() && tabbedPane.getSelectedIndex() == 0) {
                    configPanel.saveConfiguration();
                }
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return isVisible() && tabbedPane.getSelectedIndex() == 0;
            }
        };
        action.setKeyBindingData(new KeyBindingData(
            KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_S,
                java.awt.Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx())));
        action.setDescription("Save GhidraGPT configuration");
        plugin.getTool().addAction(action);
    }

    private void createShowConsoleAction() {
        DockingAction action = new DockingAction("GhidraGPT Console", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                setVisible(true);
                tabbedPane.setSelectedIndex(1);
                toFront();
                console.focusConsole();
            }
        };
        action.setKeyBindingData(new KeyBindingData(
            KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_F3, 0)));
        action.setDescription("Show GhidraGPT Console");
        plugin.getTool().addAction(action);
    }

    private void createShowDataTypesAction() {
        DockingAction action = new DockingAction("Data Type Manager", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                ComponentProvider dtProvider = plugin.getTool().getComponentProvider("DataTypes Provider");
                if (dtProvider != null) {
                    plugin.getTool().showComponentProvider(dtProvider, true);
                }
            }
        };
        action.setKeyBindingData(new KeyBindingData(
            KeyStroke.getKeyStroke(java.awt.event.KeyEvent.VK_F4, 0)));
        action.setDescription("Show Data Type Manager window");
        plugin.getTool().addAction(action);
    }

    private void createEnhanceFunctionAction() {
        DockingAction enhanceAction = new DockingAction("Rewrite Function", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                enhanceFunctionFromContext(context);
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return isValidFunctionContext(context);
            }
        };

        enhanceAction.setPopupMenuData(new MenuData(new String[] { "GhidraGPT", "Rewrite Function" }, null, "a"));
        enhanceAction.setDescription("Comprehensively rewrite function and variable names for maximum readability");

        plugin.getTool().addAction(enhanceAction);
    }

    private void createVulnerabilityAction() {
        DockingAction vulnAction = new DockingAction("Analyze Code", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                detectVulnerabilitiesFromContext(context);
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return isValidFunctionContext(context);
            }
        };

        vulnAction.setPopupMenuData(new MenuData(new String[] { "GhidraGPT", "Analyze Code" }, null, "c"));
        vulnAction.setDescription("Scan function for potential security vulnerabilities");

        plugin.getTool().addAction(vulnAction);
    }

    private void createExplainAction() {
        DockingAction explainAction = new DockingAction("Explain Code", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                explainFunctionFromContext(context);
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return isValidFunctionContext(context);
            }
        };

        explainAction.setPopupMenuData(new MenuData(new String[] { "GhidraGPT", "Explain Code" }, null, "b"));
        explainAction.setDescription("Get detailed explanation of function behavior");

        plugin.getTool().addAction(explainAction);
    }

    private void createResetLocalNamesAction() {
        DockingAction resetAction = new DockingAction("Reset Local Names", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                resetLocalNamesFromContext(context);
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return isValidFunctionContext(context);
            }
        };

        resetAction.setPopupMenuData(new MenuData(new String[] { "GhidraGPT", "Reset Local Names" }, null, "d"));
        resetAction.setDescription("Reset all user-renamed local variables and parameters to decompiler defaults");

        plugin.getTool().addAction(resetAction);
    }

    private boolean isValidFunctionContext(ActionContext context) {
        // Handle decompiler context first (most specific)
        if (context instanceof DecompilerActionContext) {
            DecompilerActionContext decompilerContext = (DecompilerActionContext) context;
            return decompilerContext.getFunction() != null;
        }

        // Handle listing context
        if (context instanceof ListingActionContext) {
            ListingActionContext listingContext = (ListingActionContext) context;
            if (listingContext.getLocation() == null || listingContext.getProgram() == null) {
                return false;
            }

            // Get function at the current address
            Program program = listingContext.getProgram();
            Address address = listingContext.getAddress();
            Function function = program.getFunctionManager().getFunctionAt(address);
            if (function != null) {
                return true;
            }

            // Check if the address is contained within any function
            function = program.getFunctionManager().getFunctionContaining(address);
            return function != null;
        }

        // Handle general program context
        if (context instanceof ProgramActionContext) {
            ProgramActionContext programContext = (ProgramActionContext) context;
            if (programContext.getProgram() == null) {
                return false;
            }

            Program program = programContext.getProgram();
            // Try to get the function from the current tool context
            ActionContext toolContext = plugin.getTool().getActiveComponentProvider().getActionContext(null);
            if (toolContext instanceof ListingActionContext) {
                ListingActionContext listingContext = (ListingActionContext) toolContext;
                if (listingContext.getAddress() != null) {
                    Function function = program.getFunctionManager().getFunctionContaining(listingContext.getAddress());
                    return function != null;
                }
            }
        }

        return false;
    }

    private Function getFunctionFromContext(ActionContext context) {
        // Handle decompiler context first (most direct)
        if (context instanceof DecompilerActionContext) {
            DecompilerActionContext decompilerContext = (DecompilerActionContext) context;
            return decompilerContext.getFunction();
        }

        // Handle listing context
        if (context instanceof ListingActionContext) {
            ListingActionContext listingContext = (ListingActionContext) context;
            if (listingContext.getLocation() == null || listingContext.getProgram() == null) {
                return null;
            }

            Program program = listingContext.getProgram();
            Address address = listingContext.getAddress();

            // First try to get function at exact address
            Function function = program.getFunctionManager().getFunctionAt(address);
            if (function != null) {
                return function;
            }

            // If not found, try to get function containing the address
            return program.getFunctionManager().getFunctionContaining(address);
        }

        // Handle general program context
        if (context instanceof ProgramActionContext) {
            ProgramActionContext programContext = (ProgramActionContext) context;
            if (programContext.getProgram() == null) {
                return null;
            }

            Program program = programContext.getProgram();
            // Try to get the function from the current tool context
            ActionContext toolContext = plugin.getTool().getActiveComponentProvider().getActionContext(null);
            if (toolContext instanceof ListingActionContext) {
                ListingActionContext listingContext = (ListingActionContext) toolContext;
                if (listingContext.getAddress() != null) {
                    Address address = listingContext.getAddress();
                    Function function = program.getFunctionManager().getFunctionAt(address);
                    if (function != null) {
                        return function;
                    }
                    return program.getFunctionManager().getFunctionContaining(address);
                }
            }
        }

        return null;
    }

    private Program getProgramFromContext(ActionContext context) {
        // Handle decompiler context
        if (context instanceof DecompilerActionContext) {
            return ((DecompilerActionContext) context).getProgram();
        }

        // Handle listing context
        if (context instanceof ListingActionContext) {
            return ((ListingActionContext) context).getProgram();
        }

        // Handle general program context
        if (context instanceof ProgramActionContext) {
            return ((ProgramActionContext) context).getProgram();
        }

        return null;
    }

    private Function getCurrentFunction() {
        if (currentProgram == null)
            return null;

        // Get the current listing context to find the selected function
        ActionContext context = plugin.getTool().getActiveComponentProvider().getActionContext(null);
        if (context instanceof ListingActionContext) {
            return getFunctionFromContext(context);
        }

        return null;
    }

    private void enhanceFunction() {
        executeAnalysis("Rewriting function...",
                (function, monitor) -> analysisService.rewriteFunction(function, currentProgram, monitor));
    }

    private void detectVulnerabilities() {
        executeAnalysis("Detecting vulnerabilities...",
                (function, monitor) -> analysisService.detectVulnerabilities(function, currentProgram, monitor));
    }

    private void explainFunction() {
        executeAnalysis("Explaining function...",
                (function, monitor) -> analysisService.explainFunction(function, currentProgram, monitor));
    }

    // Context-aware methods for context menu actions

    private void enhanceFunctionFromContext(ActionContext context) {
        Function function = getFunctionFromContext(context);
        Program program = getProgramFromContext(context);
        executeAnalysisWithContext("Rewriting function...", function, program,
                (f, p, monitor) -> analysisService.rewriteFunction(f, p, monitor));
    }

    private void detectVulnerabilitiesFromContext(ActionContext context) {
        Function function = getFunctionFromContext(context);
        Program program = getProgramFromContext(context);
        executeAnalysisWithContext("Detecting vulnerabilities...", function, program,
                (f, p, monitor) -> analysisService.detectVulnerabilities(f, p, monitor));
    }

    private void explainFunctionFromContext(ActionContext context) {
        Function function = getFunctionFromContext(context);
        Program program = getProgramFromContext(context);
        executeAnalysisWithContext("Explaining function...", function, program,
                (f, p, monitor) -> analysisService.explainFunction(f, p, monitor));
    }

    private void resetLocalNamesFromContext(ActionContext context) {
        Function function = getFunctionFromContext(context);
        Program program = getProgramFromContext(context);
        if (function == null || program == null) {
            Msg.showError(this, mainPanel, "Error", "No function selected");
            return;
        }

        int txId = program.startTransaction("Reset Locals: " + function.getName());
        try {
            int nameCount = 0;
            int typeCount = 0;

            // Reset names
            for (Variable var : function.getLocalVariables()) {
                if (var.getSource() == SourceType.USER_DEFINED) {
                    var.setName(null, SourceType.DEFAULT);
                    nameCount++;
                }
            }
            for (var param : function.getParameters()) {
                if (param.getSource() == SourceType.USER_DEFINED) {
                    param.setName(null, SourceType.DEFAULT);
                    nameCount++;
                }
            }

            // Reset types via decompiler
            DecompInterface decomp = new DecompInterface();
            decomp.setOptions(new DecompileOptions());
            try {
                decomp.openProgram(program);
                DecompileResults results = decomp.decompileFunction(function, 30, new ConsoleTaskMonitor());
                HighFunction highFunc = results.getHighFunction();
                if (highFunc != null) {
                    java.util.Iterator<HighSymbol> symbols = highFunc.getLocalSymbolMap().getSymbols();
                    while (symbols.hasNext()) {
                        HighSymbol symbol = symbols.next();
                        if (symbol.getHighVariable() != null) {
                            ghidra.program.model.data.DataType inferredType = symbol.getHighVariable().getDataType();
                            if (inferredType != null) {
                                try {
                                    HighFunctionDBUtil.updateDBVariable(symbol, symbol.getName(), inferredType, SourceType.DEFAULT);
                                    typeCount++;
                                } catch (Exception e) {
                                    // Some symbols can't be updated (e.g. compiler temps)
                                }
                            }
                        }
                    }
                }
            } finally {
                decomp.dispose();
            }

            if (console != null) {
                console.appendInfo("Reset " + nameCount + " names, " + typeCount + " types in " + function.getName());
            }
        } catch (Exception e) {
            Msg.error(this, "Failed to reset locals", e);
            program.endTransaction(txId, false);
            return;
        }
        program.endTransaction(txId, true);
    }

    private void executeAnalysis(String taskName, AnalysisTask task) {
        Function function = getCurrentFunction();
        if (function == null) {
            Msg.showError(this, mainPanel, "Error", "No function selected");
            return;
        }

        if (!configPanel.isConfigured()) {
            Msg.showError(this, mainPanel, "Error", "Please configure API settings first");
            showConfigurationTab();
            return;
        }

        // Execute analysis in background thread without showing loading dialog
        Thread analysisThread = new Thread(() -> {
            // Create a simple no-op monitor since we rely on console streaming for progress
            TaskMonitor monitor = new TaskMonitorAdapter();
            console.setActiveMonitor(monitor);

            try {
                // Switch to console tab to show streaming output
                SwingUtilities.invokeLater(() -> {
                    switchToConsoleTab();
                });

                String result = task.execute(function, monitor);

                // No need to log result - streaming console methods handle the display

            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    console.appendError(function.getName(), "Failed to analyze function: " + e.getMessage());
                });
            } finally {
                console.clearActiveMonitor();
            }
        });

        analysisThread.setName("GhidraGPT-" + taskName);
        analysisThread.start();
    }

    private void executeAnalysisWithContext(String taskName, Function function, Program program,
            AnalysisTaskWithContext task) {
        if (function == null) {
            Msg.showError(this, getComponent(), "Error", "No function selected");
            return;
        }

        if (!configPanel.isConfigured()) {
            Msg.showError(this, getComponent(), "Error", "Please configure API settings first");
            showConfigurationTab();
            return;
        }

        // Execute analysis in background thread without showing loading dialog
        Thread analysisThread = new Thread(() -> {
            // Create a simple no-op monitor since we rely on console streaming for progress
            TaskMonitor monitor = new TaskMonitorAdapter();
            console.setActiveMonitor(monitor);

            try {
                // Switch to console tab to show streaming output
                SwingUtilities.invokeLater(() -> {
                    switchToConsoleTab();
                });

                String result = task.execute(function, program, monitor);

                // No need to log result - streaming console methods handle the display

            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    console.appendError(function.getName(), "Failed to analyze function: " + e.getMessage());
                });
            } finally {
                console.clearActiveMonitor();
            }
        });

        analysisThread.setName("GhidraGPT-" + taskName);
        analysisThread.start();
    }

    @FunctionalInterface
    private interface AnalysisTask {
        String execute(Function function, TaskMonitor monitor) throws Exception;
    }

    @FunctionalInterface
    private interface AnalysisTaskWithContext {
        String execute(Function function, Program program, TaskMonitor monitor) throws Exception;
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }

    public void programActivated(Program program) {
        this.currentProgram = program;
        if (analysisService != null) {
            analysisService.dispose();
        }
        analysisService = new CodeAnalysis(plugin.getGPTService(), console, configPanel.getConfigurationManager());
        analysisService.initializeDecompiler(program);
    }

    public void programDeactivated(Program program) {
        if (analysisService != null) {
            analysisService.dispose();
            analysisService = null;
        }
        this.currentProgram = null;
    }

    @Override
    public void componentHidden() {
        // Clean up when component is hidden
    }

    /**
     * Logs analysis results to our dedicated GhidraGPT console
     */
    private void logResultToConsole(String functionName, String analysisType, String result) {
        console.appendAnalysisResult(functionName, analysisType, result);
    }

    @Override
    public void componentShown() {
        // Refresh when component is shown
    }

    public void dispose() {
        if (analysisService != null) {
            analysisService.dispose();
            analysisService = null;
        }
    }

}
