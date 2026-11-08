//! The object format a file is given by its name, as the stock system gives
//! it: the extension's media type, then that type's format, or the kind of
//! media alone where the type has none.

use crate::codes::format;
use std::ffi::OsStr;
use std::path::Path;

/// Extensions and the formats their media types have.
const BY_EXTENSION: &[(&str, u16)] = &[
    ("mp3", format::MP3),
    ("mpga", format::MP3),
    ("wav", format::WAV),
    ("wma", format::WMA),
    ("ogg", format::OGG),
    ("oga", format::OGG),
    ("aac", format::AAC),
    ("flac", format::FLAC),
    ("aif", format::AIFF),
    ("aiff", format::AIFF),
    ("aifc", format::AIFF),
    ("mpeg", format::MPEG),
    ("mpg", format::MPEG),
    ("mpe", format::MPEG),
    ("mp4", format::MP4_CONTAINER),
    ("3gp", format::THREE_GP_CONTAINER),
    ("3gpp", format::THREE_GP_CONTAINER),
    ("3g2", format::THREE_GP_CONTAINER),
    ("3gpp2", format::THREE_GP_CONTAINER),
    ("avi", format::AVI),
    ("wmv", format::WMV),
    ("asf", format::ASF),
    ("asx", format::ASF),
    ("jpg", format::EXIF_JPEG),
    ("jpeg", format::EXIF_JPEG),
    ("jpe", format::EXIF_JPEG),
    ("gif", format::GIF),
    ("png", format::PNG),
    ("bmp", format::BMP),
    ("heic", format::HEIF),
    ("heif", format::HEIF),
    ("dng", format::DNG),
    ("tif", format::TIFF),
    ("tiff", format::TIFF),
    ("cr2", format::TIFF),
    ("nrw", format::TIFF),
    ("arw", format::TIFF),
    ("rw2", format::TIFF),
    ("orf", format::TIFF),
    ("pef", format::TIFF),
    ("srw", format::TIFF),
    ("nef", format::TIFF_EP),
    ("jp2", format::JP2),
    ("jpx", format::JPX),
    ("m3u", format::M3U_PLAYLIST),
    ("pls", format::PLS_PLAYLIST),
    ("wpl", format::WPL_PLAYLIST),
    ("txt", format::TEXT),
    ("text", format::TEXT),
    ("htm", format::HTML),
    ("html", format::HTML),
    ("xml", format::XML_DOCUMENT),
    ("doc", format::MS_WORD_DOCUMENT),
    ("docx", format::MS_WORD_DOCUMENT),
    ("xls", format::MS_EXCEL_SPREADSHEET),
    ("xlsx", format::MS_EXCEL_SPREADSHEET),
    ("ppt", format::MS_POWERPOINT_PRESENTATION),
    ("pptx", format::MS_POWERPOINT_PRESENTATION),
];

/// Extensions whose media types have no format of their own, only a kind
/// of media.
const BY_KIND: &[(&str, u16)] = &[
    ("m4a", format::UNDEFINED_AUDIO),
    ("amr", format::UNDEFINED_AUDIO),
    ("awb", format::UNDEFINED_AUDIO),
    ("opus", format::UNDEFINED_AUDIO),
    ("mid", format::UNDEFINED_AUDIO),
    ("midi", format::UNDEFINED_AUDIO),
    ("m4v", format::UNDEFINED_VIDEO),
    ("mkv", format::UNDEFINED_VIDEO),
    ("webm", format::UNDEFINED_VIDEO),
    ("mov", format::UNDEFINED_VIDEO),
    ("ts", format::UNDEFINED_VIDEO),
    ("flv", format::UNDEFINED_VIDEO),
    ("webp", format::DEFINED),
    ("svg", format::DEFINED),
    ("ico", format::DEFINED),
    ("avif", format::DEFINED),
];

/// The formats the phone takes from the computer: everything a file here
/// can be given, so a file comes back as it went.
pub const ACCEPTED: &[u16] = &[
    format::UNDEFINED,
    format::ASSOCIATION,
    format::TEXT,
    format::HTML,
    format::AIFF,
    format::WAV,
    format::MP3,
    format::AVI,
    format::MPEG,
    format::ASF,
    format::DEFINED,
    format::EXIF_JPEG,
    format::TIFF_EP,
    format::BMP,
    format::GIF,
    format::JFIF,
    format::PNG,
    format::TIFF,
    format::JP2,
    format::JPX,
    format::DNG,
    format::HEIF,
    format::UNDEFINED_AUDIO,
    format::WMA,
    format::OGG,
    format::AAC,
    format::FLAC,
    format::UNDEFINED_VIDEO,
    format::WMV,
    format::MP4_CONTAINER,
    format::MP2,
    format::THREE_GP_CONTAINER,
    format::ABSTRACT_AV_PLAYLIST,
    format::WPL_PLAYLIST,
    format::M3U_PLAYLIST,
    format::PLS_PLAYLIST,
    format::XML_DOCUMENT,
    format::MS_WORD_DOCUMENT,
    format::MS_EXCEL_SPREADSHEET,
    format::MS_POWERPOINT_PRESENTATION,
];

/// The format of the entry `name`: a folder's, or the one its extension
/// gives, in any case.
pub fn of(name: &OsStr, folder: bool) -> u16 {
    if folder {
        return format::ASSOCIATION;
    }
    let Some(ext) = Path::new(name).extension().and_then(OsStr::to_str) else {
        return format::UNDEFINED;
    };
    let ext = ext.to_ascii_lowercase();
    BY_EXTENSION
        .iter()
        .chain(BY_KIND)
        .find(|(e, _)| *e == ext)
        .map_or(format::UNDEFINED, |&(_, f)| f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_take_their_extension_s_format_in_any_case() {
        assert_eq!(of(OsStr::new("IMG_0001.JPG"), false), format::EXIF_JPEG);
        assert_eq!(of(OsStr::new("song.mp3"), false), format::MP3);
        assert_eq!(of(OsStr::new("clip.Mp4"), false), format::MP4_CONTAINER);
        assert_eq!(
            of(OsStr::new("report.docx"), false),
            format::MS_WORD_DOCUMENT
        );
        assert_eq!(of(OsStr::new("voice.m4a"), false), format::UNDEFINED_AUDIO);
        assert_eq!(of(OsStr::new("film.mkv"), false), format::UNDEFINED_VIDEO);
        assert_eq!(of(OsStr::new("sticker.webp"), false), format::DEFINED);
        assert_eq!(of(OsStr::new("update.zip"), false), format::UNDEFINED);
        assert_eq!(of(OsStr::new("README"), false), format::UNDEFINED);
        assert_eq!(of(OsStr::new(".nomedia"), false), format::UNDEFINED);
    }

    #[test]
    fn a_folder_is_an_association_whatever_its_name() {
        assert_eq!(of(OsStr::new("DCIM"), true), format::ASSOCIATION);
        assert_eq!(of(OsStr::new("backup.zip"), true), format::ASSOCIATION);
    }

    #[test]
    fn every_format_a_file_is_given_is_one_the_phone_takes() {
        for &(ext, f) in BY_EXTENSION.iter().chain(BY_KIND) {
            assert!(ACCEPTED.contains(&f), "{ext} gives {f:#06x}");
        }
        assert!(ACCEPTED.contains(&format::UNDEFINED) && ACCEPTED.contains(&format::ASSOCIATION));
    }
}
