#include "fileview.hpp"

#include <QDebug>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTimer>

FileView::FileView(QObject* parent) : QObject(parent) {
  connect(&mWatcher, &QFileSystemWatcher::fileChanged, this, &FileView::onWatchFired);
  connect(&mWatcher, &QFileSystemWatcher::directoryChanged, this, &FileView::onWatchFired);
}

void FileView::setPath(const QString& path) {
  if (mPath == path) return;
  mPath = path;
  emit pathChanged();
  rewatch();
  reload();
}

void FileView::setWatchChanges(bool watch) {
  if (mWatch == watch) return;
  mWatch = watch;
  emit watchChangesChanged();
  rewatch();
}

void FileView::setPrintErrors(bool print) {
  if (mPrintErrors == print) return;
  mPrintErrors = print;
  emit printErrorsChanged();
}

void FileView::setAtomicWrites(bool atomic) {
  if (mAtomic == atomic) return;
  mAtomic = atomic;
  emit atomicWritesChanged();
  rewatch();
}

void FileView::reload() {
  const QString previous = mText;
  const bool wasThere = mExists;

  QFile file(mPath);
  if (mPath.isEmpty() || !file.exists()) {
    mExists = false;
    mText.clear();
  } else if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
    mExists = true;
    mText = QString::fromUtf8(file.readAll());
  } else {
    mExists = false;
    mText.clear();
    if (mPrintErrors)
      qWarning() << "blackbag-desktop: cannot read" << mPath << file.errorString();
  }

  if (mExists != wasThere || mText != previous || !wasThere) emit loaded();
}

void FileView::rewatch() {
  if (!mWatcher.files().isEmpty()) mWatcher.removePaths(mWatcher.files());
  if (!mWatcher.directories().isEmpty()) mWatcher.removePaths(mWatcher.directories());
  if (!mWatch || mPath.isEmpty()) return;

  // The directory is watched alongside the file. An editor or an engine that
  // writes atomically replaces the inode rather than modifying it, and a
  // file-only watch goes deaf the first time that happens.
  mWatcher.addPath(mPath);
  const QString dir = QFileInfo(mPath).absolutePath();
  if (!dir.isEmpty() && QDir(dir).exists()) mWatcher.addPath(dir);
}

void FileView::onWatchFired() {
  // Re-arm: a replaced inode drops the file watch even though the path is
  // still meaningful.
  QTimer::singleShot(0, this, [this] {
    if (mWatch && !mPath.isEmpty() && !mWatcher.files().contains(mPath)
        && QFile::exists(mPath))
      mWatcher.addPath(mPath);
  });
  emit fileChanged();
}
