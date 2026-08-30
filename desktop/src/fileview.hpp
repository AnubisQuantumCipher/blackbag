// A watched file, API-compatible with Quickshell.Io's FileView.
//
// The engine rewrites its status file after every operation, including ones
// run from a terminal. Watching that file is what keeps the vault current
// without shortening the poll interval, so the deck is right within a moment of
// a change it did not itself cause -- including a lock performed from a
// terminal while the window is open.
//
// A missing file is an ordinary state here, not an error: a machine that has
// never run the engine simply has no status file yet, and the deck draws that
// as NO VAULT rather than as a failure.
#pragma once

#include <QFileSystemWatcher>
#include <QObject>
#include <QString>
#include <QtQml/qqmlregistration.h>

class FileView : public QObject {
  Q_OBJECT
  QML_ELEMENT

  Q_PROPERTY(QString path READ path WRITE setPath NOTIFY pathChanged)
  Q_PROPERTY(bool watchChanges READ watchChanges WRITE setWatchChanges NOTIFY watchChangesChanged)
  Q_PROPERTY(bool printErrors READ printErrors WRITE setPrintErrors NOTIFY printErrorsChanged)
  Q_PROPERTY(bool atomicWrites READ atomicWrites WRITE setAtomicWrites NOTIFY atomicWritesChanged)
  Q_PROPERTY(bool exists READ exists NOTIFY loaded)

public:
  explicit FileView(QObject* parent = nullptr);

  [[nodiscard]] QString path() const { return mPath; }
  void setPath(const QString& path);

  [[nodiscard]] bool watchChanges() const { return mWatch; }
  void setWatchChanges(bool watch);

  [[nodiscard]] bool printErrors() const { return mPrintErrors; }
  void setPrintErrors(bool print);

  // The engine replaces its status file by rename, so a watch on the file's
  // own inode is dropped by the first write. Set true, this re-establishes
  // the watch on every fire; the QML was written against the Quickshell
  // property of the same name and means the same thing by it.
  [[nodiscard]] bool atomicWrites() const { return mAtomic; }
  void setAtomicWrites(bool atomic);

  [[nodiscard]] bool exists() const { return mExists; }

  // The file's contents as of the last read. Empty when the file is absent,
  // which callers must treat as "nothing stated" rather than as a value.
  Q_INVOKABLE QString text() const { return mText; }

  Q_INVOKABLE void reload();

signals:
  void pathChanged();
  void watchChangesChanged();
  void printErrorsChanged();
  void atomicWritesChanged();
  void loaded();
  void fileChanged();

private:
  void rewatch();
  void onWatchFired();

  QFileSystemWatcher mWatcher;
  QString mPath;
  QString mText;
  bool mWatch = false;
  bool mPrintErrors = true;
  bool mAtomic = false;
  bool mExists = false;
};
