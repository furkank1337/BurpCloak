package aimasker.burp.ui;

import aimasker.core.audit.LineageRecord;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import javax.swing.table.AbstractTableModel;

/** Lineage view; newest first. Contains fingerprints, never original values. */
final class LineageTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;
    private static final String[] COLUMNS = {"Time", "Entity", "Type", "Fingerprint", "Replacement", "Source", "Location"};
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());

    private transient List<LineageRecord> records = new ArrayList<>();

    void setRecords(List<LineageRecord> value) {
        List<LineageRecord> reversed = new ArrayList<>(value);
        java.util.Collections.reverse(reversed);
        records = reversed;
        fireTableDataChanged();
    }

    @Override
    public int getRowCount() {
        return records.size();
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
        LineageRecord r = records.get(row);
        return switch (column) {
            case 0 -> TIME.format(r.timestamp());
            case 1 -> r.entityId();
            case 2 -> r.type().name();
            case 3 -> r.fingerprint();
            case 4 -> r.replacement();
            case 5 -> r.source();
            default -> r.location();
        };
    }
}
