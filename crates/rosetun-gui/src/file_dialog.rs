//! The system's file dialogs: Windows' own through `rfd`, on Linux the XDG Desktop
//! Portal (`rosetun_shell::pick_file`). `rfd`'s portal backend was not taken: it loads
//! libdbus by name beside the D-Bus connection the shell already has, and it answers
//! every failure with "no file", which leaves nothing to tell the user.

use std::path::PathBuf;

/// A group of files the dialog offers.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Filter<'a> {
    pub(crate) name: &'a str,
    pub(crate) extensions: &'a [&'a str],
}

/// The system has no file dialog to ask; the caller offers typing the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Unavailable;

/// One existing file. `Ok(None)` is a cancelled dialog.
pub(crate) fn pick_file(
    title: &str,
    filter: Option<Filter<'_>>,
) -> Result<Option<PathBuf>, Unavailable> {
    #[cfg(windows)]
    {
        let mut dialog = rfd::FileDialog::new().set_title(title);
        if let Some(filter) = filter {
            dialog = dialog.add_filter(filter.name, filter.extensions);
        }
        Ok(dialog.pick_file())
    }
    #[cfg(target_os = "linux")]
    {
        let filters: Vec<rosetun_shell::FileFilter<'_>> = filter
            .map(|filter| rosetun_shell::FileFilter {
                name: filter.name,
                extensions: filter.extensions,
            })
            .into_iter()
            .collect();
        rosetun_shell::pick_file(title, &filters).map_err(unavailable)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = (title, filter);
        Err(Unavailable)
    }
}

#[cfg(target_os = "linux")]
fn unavailable(error: rosetun_shell::FileDialogError) -> Unavailable {
    // The reason is a bus or portal message; it holds no path.
    tracing::warn!(%error, "no file dialog");
    Unavailable
}
