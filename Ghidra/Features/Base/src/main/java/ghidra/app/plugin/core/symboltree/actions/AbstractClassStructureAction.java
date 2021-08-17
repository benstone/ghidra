package ghidra.app.plugin.core.symboltree.actions;

import javax.swing.tree.TreePath;

import docking.action.KeyBindingType;
import ghidra.app.plugin.core.symboltree.SymbolTreeActionContext;
import ghidra.app.plugin.core.symboltree.nodes.ClassSymbolNode;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.data.Structure;
import ghidra.program.model.symbol.Namespace;


/**
 * Abstract base class for actions that create/edit class structures
 */
public abstract class AbstractClassStructureAction extends SymbolTreeContextAction {

	public AbstractClassStructureAction(String name, String owner) {
		super(name, owner);
	}

	public AbstractClassStructureAction(String name, String owner, KeyBindingType kbType) {
		super(name, owner, kbType);
	}

	/**
	 * Returns true if the selected item in the tree is a class namespace
	 */
	protected boolean isClassSelected(SymbolTreeActionContext context) {
		// Only allow one class to be selected
		TreePath[] selectionPaths = context.getSelectedSymbolTreePaths();
		if (selectionPaths.length != 1) {
			return false;
		}

		// Check if the selected node is a class symbol node
		Object object = selectionPaths[0].getLastPathComponent();
		if (object instanceof ClassSymbolNode) {
			return true;
		}

		return false;
	}

	/**
	 * Gets the class namespace from the selected class symbol node
	 */
	protected Namespace getSelectedClassNamespace(SymbolTreeActionContext context) {
		// Get the selected class namespace

		if (!isClassSelected(context))
		{
			return null;
		}

		ClassSymbolNode classSymbolNode = (ClassSymbolNode)context.getSelectedSymbolTreePaths()[0].getLastPathComponent();
		Namespace classNamespace = classSymbolNode.getNamespace();
		return classNamespace;
	}

	/**
	 * Open a structure for editing in the Structure Editor
	 */
	protected void editStructure(SymbolTreeActionContext context, Structure classStruct)
	{
		DataTypeManagerService dataTypeManagerService = context.getComponentProvider().getTool().getService(DataTypeManagerService.class);
		if (dataTypeManagerService != null)
		{
			dataTypeManagerService.edit(classStruct);
		}
	}

	@Override
	protected boolean isEnabledForContext(SymbolTreeActionContext context) {
		// Enable these actions if the selected item is a class
		return isClassSelected(context);
	}

}