package aimasker.burp.ui;

import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.Insets;
import java.awt.LayoutManager;

/**
 * Stacks children top to bottom, each stretched to the container's width and given the height
 * it prefers at that width, so line-wrapped text areas grow and shrink with the panel.
 */
final class VerticalStack implements LayoutManager {

    private static final int GAP = 2;

    @Override
    public void addLayoutComponent(String name, Component component) {
    }

    @Override
    public void removeLayoutComponent(Component component) {
    }

    @Override
    public Dimension preferredLayoutSize(Container parent) {
        Insets insets = parent.getInsets();
        int width = contentWidth(parent);
        int height = 0;
        int widest = 0;
        for (Component child : parent.getComponents()) {
            if (child.isVisible()) {
                widest = Math.max(widest, child.getPreferredSize().width);
                height += heightAt(child, width > 0 ? width : child.getPreferredSize().width) + GAP;
            }
        }
        int preferredWidth = width > 0 ? width : widest;
        return new Dimension(preferredWidth + insets.left + insets.right, height + insets.top + insets.bottom);
    }

    @Override
    public Dimension minimumLayoutSize(Container parent) {
        Insets insets = parent.getInsets();
        int width = 0;
        for (Component child : parent.getComponents()) {
            if (child.isVisible()) {
                width = Math.max(width, child.getMinimumSize().width);
            }
        }
        return new Dimension(width + insets.left + insets.right, preferredLayoutSize(parent).height);
    }

    @Override
    public void layoutContainer(Container parent) {
        Insets insets = parent.getInsets();
        int width = contentWidth(parent);
        int y = insets.top;
        for (Component child : parent.getComponents()) {
            if (child.isVisible()) {
                int height = heightAt(child, width);
                child.setBounds(insets.left, y, width, height);
                y += height + GAP;
            }
        }
    }

    private static int contentWidth(Container parent) {
        Insets insets = parent.getInsets();
        return Math.max(0, parent.getWidth() - insets.left - insets.right);
    }

    /** Wrapped text reports its preferred height for its current width, so size it first. */
    private static int heightAt(Component child, int width) {
        if (width > 0 && child.getWidth() != width) {
            child.setSize(width, Math.max(child.getHeight(), 1));
        }
        return child.getPreferredSize().height;
    }
}
