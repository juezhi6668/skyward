//! The editor page: a text file's lines, the cursor among them, and how far
//! down the rows the lines wrap to the view stands, drawn on a card as the
//! terminal draws its screen. The lines wrap at the card's width, each
//! character taking the columns a terminal gives it, and the file is
//! written back with the line endings it had.

use crate::canvas::Canvas;
use crate::color::mix;
use crate::font::Fonts;
use crate::geom::Rect;
use crate::term::{self, Layout, TermKey};
use crate::theme::Theme;
use crate::widgets::{self, Caret};
use unicode_width::UnicodeWidthChar;

/// The most of a file the editor takes.
pub const MAX_BYTES: u64 = 2 << 20;

/// The columns from one tab stop to the next.
const TAB: usize = 4;

/// The keys of the editor's own row, above the keyboard, in the order the
/// row shows them.
pub const EDITOR_KEYS: [TermKey; 5] = [
    TermKey::Tab,
    TermKey::Left,
    TermKey::Up,
    TermKey::Down,
    TermKey::Right,
];

#[derive(Clone, Debug, PartialEq)]
pub struct Editor {
    /// Where the file is.
    pub path: String,
    lines: Vec<String>,
    /// The file's lines all ended in CR LF.
    crlf: bool,
    /// How many rows each line wraps to.
    rows: Vec<usize>,
    cols: usize,
    /// The cursor: its line, and how many characters into it.
    line: usize,
    at: usize,
    /// The cursor stands at the end of the row before, where its place is
    /// also the start of the next: past the end of a row the line wraps
    /// after.
    tail: bool,
    /// The column moving up and down keeps to, from where the cursor was
    /// last put along a row.
    goal: Option<usize>,
    /// The first row in view, and how many the view shows.
    top: usize,
    view: usize,
    /// Changed since it was read or last saved.
    pub changed: bool,
}

/// How many columns `ch` takes from column `x` of a row: a tab to the next
/// stop, a control character two, shown as `^` and a letter, a character a
/// terminal draws wide two, any other one.
pub fn advance(ch: char, x: usize) -> usize {
    match ch {
        '\t' => TAB - x % TAB,
        c if c.is_control() => 2,
        c => c.width().unwrap_or(1).max(1),
    }
}

/// What a control character shows as: `^M` for a carriage return, `^[` for
/// escape, `^?` for delete.
fn notation(ch: char) -> String {
    let letter = char::from_u32((ch as u32 & 0x7f) ^ 0x40).expect("seven bits make a character");
    format!("^{letter}")
}

/// Where each row of `line` starts, by character, wrapped at `cols`: a
/// character goes to the next row where it would reach past the last
/// column.
fn breaks(line: &str, cols: usize) -> Vec<usize> {
    let mut out = vec![0];
    let mut x = 0;
    for (n, ch) in line.chars().enumerate() {
        if x > 0 && x + advance(ch, x) > cols {
            out.push(n);
            x = 0;
        }
        x += advance(ch, x);
    }
    out
}

/// The byte where character `at` of `line` starts, or its end.
fn byte(line: &str, at: usize) -> usize {
    line.char_indices().nth(at).map_or(line.len(), |(i, _)| i)
}

impl Editor {
    /// The file at `path` holding `text`, wrapped at `cols` and seen `view`
    /// rows at a time, the cursor at its start.
    pub fn new(path: String, text: &str, cols: usize, view: usize) -> Editor {
        let crlf =
            text.contains("\r\n") && text.matches('\n').count() == text.matches("\r\n").count();
        let lines: Vec<String> = text
            .split(if crlf { "\r\n" } else { "\n" })
            .map(str::to_string)
            .collect();
        let rows = lines.iter().map(|l| breaks(l, cols).len()).collect();
        Editor {
            path,
            lines,
            crlf,
            rows,
            cols,
            line: 0,
            at: 0,
            tail: false,
            goal: None,
            top: 0,
            view,
            changed: false,
        }
    }

    /// The file as it is to be written.
    pub fn text(&self) -> String {
        self.lines.join(if self.crlf { "\r\n" } else { "\n" })
    }

    /// The first row in view.
    pub fn top(&self) -> usize {
        self.top
    }

    /// The row of the first row of `line`.
    fn first_row(&self, line: usize) -> usize {
        self.rows[..line].iter().sum()
    }

    /// The line holding `row`, and which of its rows that is; past the last
    /// row, the last line's last row.
    fn line_of(&self, row: usize) -> (usize, usize) {
        let mut first = 0;
        for (line, &n) in self.rows.iter().enumerate() {
            if row < first + n {
                return (line, row - first);
            }
            first += n;
        }
        let last = self.lines.len() - 1;
        (last, self.rows[last] - 1)
    }

    /// The cursor's row and column.
    pub fn cursor(&self) -> (usize, usize) {
        let text = &self.lines[self.line];
        let b = breaks(text, self.cols);
        let mut r = b.partition_point(|&s| s <= self.at) - 1;
        if self.tail && r > 0 && b[r] == self.at {
            r -= 1;
        }
        let mut x = 0;
        for ch in text.chars().skip(b[r]).take(self.at - b[r]) {
            x += advance(ch, x);
        }
        (self.first_row(self.line) + r, x)
    }

    /// The text of each row in view.
    pub fn visible(&self) -> Vec<&str> {
        let end = self.top + self.view;
        let mut out = Vec::new();
        let mut row = 0;
        for (line, text) in self.lines.iter().enumerate() {
            if row >= end {
                break;
            }
            if row + self.rows[line] > self.top {
                let b = breaks(text, self.cols);
                for (r, &start) in b.iter().enumerate() {
                    if (self.top..end).contains(&(row + r)) {
                        let stop = b.get(r + 1).map_or(text.len(), |&s| byte(text, s));
                        out.push(&text[byte(text, start)..stop]);
                    }
                }
            }
            row += self.rows[line];
        }
        out
    }

    /// Put the cursor at column `x` of `row`, between the characters
    /// nearest it.
    pub fn place(&mut self, row: usize, x: f32) {
        self.go(row, x);
        self.goal = None;
    }

    fn go(&mut self, row: usize, x: f32) {
        let (line, r) = self.line_of(row);
        let text = &self.lines[line];
        let b = breaks(text, self.cols);
        let end = b
            .get(r + 1)
            .copied()
            .unwrap_or_else(|| text.chars().count());
        let mut at = b[r];
        let mut reach = 0;
        for ch in text.chars().skip(at).take(end - at) {
            let w = advance(ch, reach);
            if x < reach as f32 + w as f32 / 2.0 {
                break;
            }
            reach += w;
            at += 1;
        }
        self.tail = at == end && r + 1 < b.len();
        (self.line, self.at) = (line, at);
    }

    /// Move the cursor a character back, to the end of the line before at
    /// the start of its own.
    pub fn left(&mut self) {
        if self.at > 0 {
            self.at -= 1;
        } else if self.line > 0 {
            self.line -= 1;
            self.at = self.lines[self.line].chars().count();
        }
        self.tail = false;
        self.goal = None;
        self.follow();
    }

    /// Move the cursor a character on, to the start of the next line at the
    /// end of its own.
    pub fn right(&mut self) {
        if self.at < self.lines[self.line].chars().count() {
            self.at += 1;
        } else if self.line + 1 < self.lines.len() {
            self.line += 1;
            self.at = 0;
        }
        self.tail = false;
        self.goal = None;
        self.follow();
    }

    /// Move the cursor a row up, keeping to its column; from the first row,
    /// to the start.
    pub fn up(&mut self) {
        let (row, x) = self.cursor();
        let goal = *self.goal.get_or_insert(x);
        if row == 0 {
            (self.line, self.at, self.tail) = (0, 0, false);
        } else {
            self.go(row - 1, goal as f32);
        }
        self.follow();
    }

    /// Move the cursor a row down, keeping to its column; from the last
    /// row, to the end.
    pub fn down(&mut self) {
        let (row, x) = self.cursor();
        let goal = *self.goal.get_or_insert(x);
        if row + 1 >= self.rows.iter().sum() {
            self.line = self.lines.len() - 1;
            self.at = self.lines[self.line].chars().count();
            self.tail = false;
        } else {
            self.go(row + 1, goal as f32);
        }
        self.follow();
    }

    /// Type `ch` at the cursor.
    pub fn insert(&mut self, ch: char) {
        let text = &mut self.lines[self.line];
        text.insert(byte(text, self.at), ch);
        self.at += 1;
        self.edited(self.line);
    }

    /// Break the line at the cursor, which goes to the start of the new one.
    pub fn newline(&mut self) {
        let text = &mut self.lines[self.line];
        let rest = text.split_off(byte(text, self.at));
        self.lines.insert(self.line + 1, rest);
        self.rows.insert(self.line + 1, 0);
        self.edited(self.line);
        self.line += 1;
        self.at = 0;
        self.edited(self.line);
    }

    /// Take away the character before the cursor; at the start of a line,
    /// join it to the line before.
    pub fn backspace(&mut self) {
        if self.at > 0 {
            let text = &mut self.lines[self.line];
            text.remove(byte(text, self.at - 1));
            self.at -= 1;
            self.edited(self.line);
        } else if self.line > 0 {
            let rest = self.lines.remove(self.line);
            self.rows.remove(self.line);
            self.line -= 1;
            let text = &mut self.lines[self.line];
            self.at = text.chars().count();
            text.push_str(&rest);
            self.edited(self.line);
        }
    }

    /// `line` changed: wrap it again, and keep the cursor in view.
    fn edited(&mut self, line: usize) {
        self.rows[line] = breaks(&self.lines[line], self.cols).len();
        self.changed = true;
        self.tail = false;
        self.goal = None;
        self.follow();
    }

    /// Scroll the view so the cursor's row is in it.
    fn follow(&mut self) {
        let (row, _) = self.cursor();
        if row < self.top {
            self.top = row;
        } else if row >= self.top + self.view {
            self.top = row + 1 - self.view;
        }
    }

    /// Scroll the view `rows` rows down the text, or up for fewer than
    /// none, no further than the last row at the bottom of the view.
    pub fn scroll(&mut self, rows: isize) {
        let last = self.rows.iter().sum::<usize>().saturating_sub(self.view);
        self.top = self.top.saturating_add_signed(rows).min(last);
    }

    /// The file was written as it stands.
    pub fn saved(&mut self) {
        self.changed = false;
    }
}

/// Where the editor page's card and keys stand: the card under the caption
/// saying where the file is, which stands as a page's first section does.
pub fn layout(t: &Theme, f: &Fonts) -> Layout {
    let m = &t.m;
    term::layout(
        t,
        f,
        m.content_top - m.section_label_top + m.dp(2.0) + m.section_block,
    )
}

/// Draw where the file is as the caption over the card: a path too long
/// for the line gives up its start, keeping the file's name.
pub fn caption(c: &mut Canvas, t: &Theme, f: &Fonts, path: &str) {
    let m = &t.m;
    let room = m.w as f32 - (m.margin + m.inner) * 2.0;
    let mut shown = path.to_string();
    let mut rest = path.chars();
    while c.text_width(&f.label, &shown, m.label_px) > room {
        rest.next();
        shown = format!("…{}", rest.as_str());
    }
    widgets::section_first(c, t, f, m.content_top, &shown);
}

/// Draw the card and the rows of the file in view on it; give the cursor,
/// while it is in view, to lay over them as it blinks.
pub fn draw(c: &mut Canvas, t: &Theme, f: &Fonts, l: &Layout, ed: &Editor) -> Option<Caret> {
    c.fill_round_rect(
        l.card.x,
        l.card.y,
        l.card.w,
        l.card.h,
        t.m.card_radius,
        t.pal.card,
    );
    let rows = ed.visible();
    for (i, text) in rows.iter().enumerate() {
        text_row(c, t, f, l, l.x0, l.y0 + i as f32 * l.pitch, text);
    }
    let (row, x) = ed.cursor();
    let i = row.checked_sub(ed.top()).filter(|&i| i < rows.len())?;
    let y = l.y0 + i as f32 * l.pitch;
    let base = y - f.body.ink(l.px).0;
    let (top, bottom) = f.mono.line(l.px);
    let at = widgets::caret_rect(t, l.x0 + x as f32 * l.cell, base + top, base + bottom);
    // The text goes over the cursor, as a text field draws them.
    Some(widgets::caret_over(at, |art, dx, dy| {
        art.clear(t.pal.card);
        widgets::draw_caret(
            art,
            t,
            Rect {
                x: at.x - dx,
                y: at.y - dy,
                ..at
            },
        );
        text_row(art, t, f, l, l.x0 - dx, y - dy, rows[i]);
    }))
}

/// Draw a row of the file from `x0`, its top at `y`: each character in the
/// cells it takes, a tab as the room to its stop, and a control character
/// dimmed as `^` and a letter.
fn text_row(c: &mut Canvas, t: &Theme, f: &Fonts, l: &Layout, x0: f32, y: f32, text: &str) {
    // Every row sits on the baseline the UI face would give it, as the
    // terminal's rows do.
    let base = y - f.body.ink(l.px).0;
    let mut col = 0;
    let mut buf = [0u8; 4];
    for ch in text.chars() {
        let w = advance(ch, col);
        if ch != ' ' && ch != '\t' {
            let control = ch.is_control().then(|| notation(ch));
            let glyph = control
                .as_deref()
                .unwrap_or_else(|| ch.encode_utf8(&mut buf));
            let ink = if control.is_some() {
                mix(t.pal.text, t.pal.card, 0.45)
            } else {
                t.pal.text
            };
            let face = if glyph.chars().all(|g| f.mono.has(g)) {
                &f.mono
            } else {
                &f.body
            };
            let gw = c.text_width(face, glyph, l.px);
            c.text(
                face,
                glyph,
                x0 + col as f32 * l.cell + (l.cell * w as f32 - gw) / 2.0,
                base,
                l.px,
                ink,
                None,
            );
        }
        col += w;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn typed(ed: &mut Editor, text: &str) {
        for ch in text.chars() {
            if ch == '\n' {
                ed.newline();
            } else {
                ed.insert(ch);
            }
        }
    }

    #[test]
    fn lines_wrap_at_the_width_by_the_columns_each_character_takes() {
        let ed = Editor::new("/a".into(), "abcdefghij\nabcd\n中文字符\n\tx\n", 4, 20);
        assert_eq!(
            ed.visible(),
            ["abcd", "efgh", "ij", "abcd", "中文", "字符", "\t", "x", ""]
        );
        assert_eq!(advance('中', 0), 2);
        assert_eq!(advance('\r', 0), 2, "shown as ^M");
        assert_eq!(
            (advance('\t', 0), advance('\t', 1), advance('\t', 3)),
            (4, 3, 1),
            "a tab reaches the next stop"
        );
        assert_eq!(notation('\r'), "^M");
        assert_eq!(notation('\x7f'), "^?");
    }

    #[test]
    fn the_text_comes_back_with_the_line_endings_it_had() {
        for text in ["a\nb\n", "a\r\nb\r\n", "a\r\nb\nc", "", "no ending"] {
            assert_eq!(Editor::new("/a".into(), text, 40, 10).text(), text);
        }
        let mut ed = Editor::new("/a".into(), "a\r\nb\r\n", 40, 10);
        ed.down();
        typed(&mut ed, "x\ny");
        assert_eq!(
            ed.text(),
            "a\r\nx\r\nyb\r\n",
            "lines typed end as the file's do"
        );
        let mixed = Editor::new("/a".into(), "a\r\nb\n", 40, 10);
        assert_eq!(
            mixed.visible(),
            ["a\r", "b", ""],
            "a file of mixed endings shows its carriage returns"
        );
    }

    #[test]
    fn typing_inserts_breaks_and_joins_lines_at_the_cursor() {
        let mut ed = Editor::new("/a".into(), "echo hi\n", 40, 10);
        assert!(!ed.changed);
        typed(&mut ed, "#!/bin/sh\n");
        assert_eq!(ed.text(), "#!/bin/sh\necho hi\n");
        assert!(ed.changed);
        ed.backspace();
        assert_eq!(
            ed.text(),
            "#!/bin/shecho hi\n",
            "at the start of a line, it joins the line before"
        );
        assert_eq!(ed.cursor(), (0, 9));
        ed.backspace();
        ed.insert('中');
        assert_eq!(ed.text(), "#!/bin/s中echo hi\n");
        assert_eq!(ed.cursor(), (0, 10), "a wide character takes two columns");
        ed.saved();
        assert!(!ed.changed);
        let mut start = Editor::new("/a".into(), "x", 40, 10);
        start.backspace();
        assert_eq!(
            (start.text().as_str(), start.changed),
            ("x", false),
            "nothing is before the start"
        );
    }

    #[test]
    fn the_cursor_moves_along_and_across_lines_and_keeps_its_column_going_up_and_down() {
        let mut ed = Editor::new("/a".into(), "long line\nab\nanother line", 40, 10);
        for _ in 0..7 {
            ed.right();
        }
        assert_eq!(ed.cursor(), (0, 7));
        ed.down();
        assert_eq!(
            ed.cursor(),
            (1, 2),
            "a short line takes the cursor to its end"
        );
        ed.down();
        assert_eq!(ed.cursor(), (2, 7), "the column it had comes back");
        ed.down();
        assert_eq!(ed.cursor(), (2, 12), "from the last row, the end");
        ed.up();
        ed.up();
        assert_eq!(ed.cursor(), (0, 7));
        ed.up();
        assert_eq!(ed.cursor(), (0, 0), "from the first row, the start");
        ed.left();
        assert_eq!(ed.cursor(), (0, 0));
        ed.place(1, 0.0);
        ed.left();
        assert_eq!(
            ed.cursor(),
            (0, 9),
            "back from a line's start, the end of the line before"
        );
        ed.right();
        assert_eq!(ed.cursor(), (1, 0));
    }

    #[test]
    fn a_tap_puts_the_cursor_between_the_nearest_characters() {
        let mut ed = Editor::new("/a".into(), "abcdefghij\n中文", 4, 10);
        ed.place(0, 1.3);
        assert_eq!(ed.cursor(), (0, 1));
        ed.place(0, 1.7);
        assert_eq!(
            ed.cursor(),
            (0, 2),
            "the nearer side of the character tapped"
        );
        ed.place(1, 9.0);
        assert_eq!(
            ed.cursor(),
            (1, 4),
            "past a row the line wraps after, the end of that row"
        );
        ed.insert('x');
        assert_eq!(
            ed.text(),
            "abcdefghxij\n中文",
            "what is typed there goes after the row's last character"
        );
        ed.place(2, 9.0);
        assert_eq!(ed.cursor(), (2, 3), "past the line's last row, its end");
        ed.place(3, 0.9);
        assert_eq!(ed.cursor(), (3, 0), "the nearer side of a wide character");
        ed.place(3, 1.1);
        assert_eq!(ed.cursor(), (3, 2));
        ed.place(30, 0.0);
        assert_eq!(ed.cursor(), (3, 0), "below the text, the last row");
        ed.right();
        ed.down();
        assert_eq!(
            ed.cursor(),
            (3, 4),
            "down from the last row goes to the end"
        );
    }

    #[test]
    fn moving_down_keeps_to_the_column_across_wrapped_rows() {
        let mut ed = Editor::new("/a".into(), "abcdefgh\nab", 4, 10);
        ed.place(0, 3.0);
        ed.down();
        assert_eq!(ed.cursor(), (1, 3), "the next row of the same line");
        ed.down();
        assert_eq!(ed.cursor(), (2, 2), "a short line, its end");
        ed.up();
        assert_eq!(ed.cursor(), (1, 3));
        ed.place(0, 9.0);
        assert_eq!(ed.cursor(), (0, 4), "a wrapped row's end");
        ed.down();
        assert_eq!(ed.cursor(), (1, 4), "and the next row's");
    }

    #[test]
    fn the_view_follows_the_cursor_and_scrolls_no_further_than_the_text() {
        let text: String = (0..30).map(|n| format!("line {n}\n")).collect();
        let mut ed = Editor::new("/a".into(), &text, 40, 10);
        for _ in 0..12 {
            ed.down();
        }
        assert_eq!(ed.top(), 3, "the cursor's row at the bottom of the view");
        ed.scroll(100);
        assert_eq!(ed.top(), 21, "the last row at the bottom");
        ed.scroll(-100);
        assert_eq!(ed.top(), 0);
        ed.scroll(15);
        ed.insert('x');
        assert_eq!(ed.top(), 12, "typing brings the cursor back into view");
        assert_eq!(ed.visible()[0], "xline 12");
        let mut short = Editor::new("/a".into(), "a\nb", 40, 10);
        short.scroll(4);
        assert_eq!(
            short.top(),
            0,
            "text shorter than the view stays at its top"
        );
    }

    #[test]
    fn the_card_sits_under_the_caption_and_the_cursor_shows_where_it_is() {
        let t = Theme::light(1440, 3200, 3.5);
        let f = crate::font::bundled();
        let mut c = Canvas::new(t.m.w, t.m.h);
        let l = layout(&t, &f);
        assert_eq!(
            widgets::section_first(&mut c, &t, &f, t.m.content_top, "/a"),
            l.card.y
        );
        caption(&mut c, &t, &f, &"/very/long".repeat(40));
        let mut ed = Editor::new(
            "/system/build.prop".into(),
            "ro.a=1\n",
            l.cols as usize,
            l.rows as usize,
        );
        let caret = draw(&mut c, &t, &f, &l, &ed).expect("the cursor is in view");
        assert!(
            (caret.x as f32 + 1.0 - l.x0).abs() <= 1.0,
            "at the start of the first row"
        );
        ed.place(0, 3.0);
        let caret = draw(&mut c, &t, &f, &l, &ed).expect("the cursor is in view");
        assert!((caret.x as f32 + 1.0 - (l.x0 + 3.0 * l.cell)).abs() <= 1.0);
        let text: String = (0..200).map(|n| format!("line {n}\n")).collect();
        let mut long = Editor::new("/a".into(), &text, l.cols as usize, l.rows as usize);
        long.scroll(50);
        assert!(
            draw(&mut c, &t, &f, &l, &long).is_none(),
            "a cursor scrolled out of view does not show"
        );
    }
}
