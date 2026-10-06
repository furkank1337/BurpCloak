package aimasker.burp;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Converts a styled HTML report to PDF using a headless Chrome/Chromium already on the system, so
 * the extension needs no PDF library and keeps its "no runtime dependencies" promise. If no
 * browser is found the caller falls back to saving the HTML for a manual Print to PDF.
 */
public final class PdfExporter {

    /** Thrown when no usable browser is found or the conversion fails. */
    public static final class PdfUnavailableException extends Exception {
        private static final long serialVersionUID = 1L;

        PdfUnavailableException(String message) {
            super(message);
        }
    }

    private static final String[] PATH_NAMES = {
        "google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome",
        "brave-browser", "microsoft-edge", "msedge"
    };
    private static final String[] ABSOLUTE = {
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
    };

    private PdfExporter() {
    }

    /**
     * Renders {@code html} to {@code target} as PDF.
     *
     * @return the browser executable used
     * @throws PdfUnavailableException if no browser is available or it failed
     */
    public static String toPdf(String html, File target) throws PdfUnavailableException, IOException {
        String browser = findBrowser();
        if (browser == null) {
            throw new PdfUnavailableException("No Chrome/Chromium/Edge found on PATH or in the usual locations.");
        }
        File temp = File.createTempFile("cloak-report-", ".html");
        temp.deleteOnExit();
        Files.writeString(temp.toPath(), html, StandardCharsets.UTF_8);
        String url = temp.toURI().toString();

        // "--headless=new" is Chrome 109+; retry with the legacy flag for older builds.
        for (String headless : new String[] {"--headless=new", "--headless"}) {
            if (run(browser, headless, target, url) && target.isFile() && target.length() > 0) {
                temp.delete();
                return browser;
            }
        }
        temp.delete();
        throw new PdfUnavailableException("Found " + browser + " but the PDF conversion produced no output.");
    }

    private static boolean run(String browser, String headless, File target, String url) {
        List<String> cmd = new ArrayList<>();
        cmd.add(browser);
        cmd.add(headless);
        cmd.add("--disable-gpu");
        cmd.add("--no-sandbox");
        cmd.add("--no-pdf-header-footer");
        cmd.add("--print-to-pdf=" + target.getAbsolutePath());
        cmd.add(url);
        try {
            Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            if (!p.waitFor(90, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                return false;
            }
            return p.exitValue() == 0;
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return false;
        }
    }

    private static String findBrowser() {
        for (String abs : ABSOLUTE) {
            File f = new File(abs);
            if (f.isFile() && f.canExecute()) {
                return f.getAbsolutePath();
            }
        }
        String path = System.getenv("PATH");
        if (path != null) {
            String[] dirs = path.split(File.pathSeparator);
            for (String name : PATH_NAMES) {
                for (String dir : dirs) {
                    File f = new File(dir, name);
                    File exe = f.isFile() ? f : new File(dir, name + ".exe");
                    if (exe.isFile() && exe.canExecute()) {
                        return exe.getAbsolutePath();
                    }
                }
            }
        }
        return null;
    }
}
