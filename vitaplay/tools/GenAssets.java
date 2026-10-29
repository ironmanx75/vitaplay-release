import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.GradientPaint;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.geom.RoundRectangle2D;
import java.awt.image.BufferedImage;
import java.io.File;
import java.nio.file.Files;
import javax.imageio.ImageIO;

/** Generates the LiveArea images. The Vita expects 8-bit indexed PNGs, so each is quantized. */
public class GenAssets {
    static final Color TOP = new Color(0x1f, 0x2a, 0x44);
    static final Color BOTTOM = new Color(0x0b, 0x0e, 0x16);
    static final Color ACCENT = new Color(0x3d, 0xd6, 0x8c);

    public static void main(String[] args) throws Exception {
        File root = new File(args.length > 0 ? args[0] : "sce_sys");
        File contents = new File(root, "livearea/contents");
        contents.mkdirs();
        write(icon(128), new File(root, "icon0.png"));
        write(banner(840, 500, 64), new File(contents, "bg.png"));
        write(banner(280, 158, 30), new File(contents, "startup.png"));
        Files.writeString(new File(contents, "template.xml").toPath(),
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                + "<livearea style=\"a1\" format-ver=\"01.00\" content-rev=\"1\">\n"
                + "  <livearea-background>\n    <image>bg.png</image>\n  </livearea-background>\n"
                + "  <gate>\n    <startup-image>startup.png</startup-image>\n  </gate>\n"
                + "</livearea>\n");
    }

    static Graphics2D canvas(BufferedImage image) {
        Graphics2D g = image.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
        g.setPaint(new GradientPaint(0, 0, TOP, 0, image.getHeight(), BOTTOM));
        g.fillRect(0, 0, image.getWidth(), image.getHeight());
        return g;
    }

    /** A rounded "screen" with a play triangle: a handheld showing a projected display. */
    static void glyph(Graphics2D g, double cx, double cy, double w) {
        double h = w * 0.62;
        g.setColor(ACCENT);
        g.setStroke(new BasicStroke((float) (w * 0.07)));
        g.draw(new RoundRectangle2D.Double(cx - w / 2, cy - h / 2, w, h, w * 0.18, w * 0.18));
        int[] xs = {(int) (cx - w * 0.12), (int) (cx - w * 0.12), (int) (cx + w * 0.17)};
        int[] ys = {(int) (cy - h * 0.25), (int) (cy + h * 0.25), (int) cy};
        g.fillPolygon(xs, ys, 3);
    }

    static BufferedImage icon(int size) {
        BufferedImage image = new BufferedImage(size, size, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = canvas(image);
        glyph(g, size / 2.0, size * 0.42, size * 0.66);
        g.setColor(Color.WHITE);
        g.setFont(new Font(Font.SANS_SERIF, Font.BOLD, size / 6));
        centered(g, "VitaPlay", size / 2, (int) (size * 0.88));
        g.dispose();
        return image;
    }

    static BufferedImage banner(int w, int h, int fontSize) {
        BufferedImage image = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = canvas(image);
        glyph(g, w / 2.0, h * 0.38, Math.min(w, h) * 0.45);
        g.setColor(Color.WHITE);
        g.setFont(new Font(Font.SANS_SERIF, Font.BOLD, fontSize));
        centered(g, "VitaPlay", w / 2, (int) (h * 0.82));
        g.dispose();
        return image;
    }

    static void centered(Graphics2D g, String text, int cx, int baseline) {
        FontMetrics m = g.getFontMetrics();
        g.drawString(text, cx - m.stringWidth(text) / 2, baseline);
    }

    static void write(BufferedImage rgb, File file) throws Exception {
        BufferedImage indexed = new BufferedImage(rgb.getWidth(), rgb.getHeight(), BufferedImage.TYPE_BYTE_INDEXED);
        Graphics2D g = indexed.createGraphics();
        g.drawImage(rgb, 0, 0, null);
        g.dispose();
        ImageIO.write(indexed, "png", file);
    }
}
