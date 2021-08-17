package ghidra.app.plugin.core.symboltree.actions;

import docking.action.MenuData;
import ghidra.app.plugin.core.symboltree.SymbolTreeActionContext;
import ghidra.app.plugin.core.symboltree.SymbolTreePlugin;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.VariableUtilities;
import ghidra.program.model.symbol.Namespace;

public class CreateClassStructureAction extends AbstractClassStructureAction {


	public CreateClassStructureAction(SymbolTreePlugin plugin, String group, String subGroup) {
		super("Create Class Structure", plugin.getName());
		MenuData menuData = new MenuData(new String[] { "Create Class Structure" }, group);
		menuData.setMenuSubGroup(subGroup);
		setPopupMenuData(menuData);
		setEnabled(false);
	}

	@Override
	public boolean isAddToPopup(SymbolTreeActionContext context) {

		// Add to the popup if the selected class does not have a structure defined

		if (isClassSelected(context))
		{
			Namespace classNamespace = getSelectedClassNamespace(context);
			Structure classStructure = VariableUtilities.findExistingClassStruct((GhidraClass) classNamespace, context.getProgram().getDataTypeManager());
			if (classStructure == null)
			{
				return true;
			}
		}

		return false;
	}

	@Override
	protected void actionPerformed(SymbolTreeActionContext context) {

		// Create the structure for this class
		Namespace classNamespace = getSelectedClassNamespace(context);
		Structure classStruct = VariableUtilities.findOrCreateClassStruct((GhidraClass)classNamespace, context.getProgram().getDataTypeManager());

		// Open the data type manager to edit the structure
		if (classStruct != null)
		{
			editStructure(context, classStruct);
		}
	}

}
