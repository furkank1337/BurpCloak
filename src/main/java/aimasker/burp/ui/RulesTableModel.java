package aimasker.burp.ui;

import aimasker.core.domain.DomainRule;
import aimasker.core.keyword.KeywordDetector;
import java.util.ArrayList;
import java.util.List;
import javax.swing.table.AbstractTableModel;

/**
 * Target / replacement / keyword table. Keywords derived automatically from the domain are
 * shown with an "(auto)" suffix and are not stored when the cell is edited.
 */
final class RulesTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;
    private static final String[] COLUMNS = {"Target Domain", "Replacement", "Brand Keywords (comma-separated)"};
    static final int REPLACEMENT = 1;
    static final int KEYWORDS = 2;

    /** Receives user edits; implementations validate and apply them. */
    interface EditHandler {
        void edit(DomainRule rule, int column, String value);
    }

    private final transient EditHandler editHandler;
    private transient List<DomainRule> rules = new ArrayList<>();
    private boolean autoKeywords;

    RulesTableModel(EditHandler editHandler) {
        this.editHandler = editHandler;
    }

    void setRules(List<DomainRule> value, boolean autoBrandKeywords) {
        rules = new ArrayList<>(value);
        autoKeywords = autoBrandKeywords;
        fireTableDataChanged();
    }

    DomainRule ruleAt(int row) {
        return rules.get(row);
    }

    @Override
    public int getRowCount() {
        return rules.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public Object getValueAt(int row, int column) {
        DomainRule rule = rules.get(row);
        return switch (column) {
            case 0 -> rule.target();
            case REPLACEMENT -> rule.replacement();
            default -> String.join(", ", KeywordDetector.effectiveKeywords(rule, autoKeywords));
        };
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return column == REPLACEMENT || column == KEYWORDS;
    }

    @Override
    public void setValueAt(Object value, int row, int column) {
        if (value != null && !value.equals(getValueAt(row, column))) {
            editHandler.edit(rules.get(row), column, value.toString());
        }
    }

    /** Manual keywords from an edited cell, dropping the displayed "(auto)" entries. */
    static List<String> manualKeywords(String cell) {
        List<String> keywords = new ArrayList<>();
        for (String keyword : DomainRule.parseKeywords(cell)) {
            if (!keyword.endsWith("(auto)")) {
                keywords.add(keyword);
            }
        }
        return keywords;
    }
}
