// Everything the deck needs from the desktop that is not a child process.
//
// Locating the engine, the clipboard, the runtime directory, settings, and
// the theme palette. Each one used to be a service the plugin borrowed from
// its shell host; a standalone application owns them, so the only binary this
// program still executes is `black-bag` itself.
//
// Nothing here performs cryptography, derives a key, or holds a secret. It
// reads two files, writes one settings file, and answers questions about the
// machine. The clipboard is the single exception, and even there the bytes
// arrive from the engine and are never retained: see copyToClipboard.
#pragma once

#include <QColor>
#include <QFileSystemWatcher>
#include <QObject>
#include <QString>
#include <QVariantMap>
#include <QtQml/qqmlregistration.h>

class App : public QObject {
  Q_OBJECT
  QML_ELEMENT
  QML_SINGLETON

  Q_PROPERTY(QString home READ home CONSTANT)
  Q_PROPERTY(QString configPath READ configPath CONSTANT)
  Q_PROPERTY(QString appVersion READ appVersion CONSTANT)
  Q_PROPERTY(QVariantMap settings READ settings NOTIFY settingsChanged)
  Q_PROPERTY(QVariantMap palette READ palette NOTIFY paletteChanged)

public:
  explicit App(QObject* parent = nullptr);

  static App* instance();

  [[nodiscard]] QString home() const;
  [[nodiscard]] QString configPath() const;
  [[nodiscard]] QString appVersion() const;

  // Kept for the QML the plugin was written against, which asked the shell
  // host for XDG_RUNTIME_DIR rather than assuming one.
  Q_INVOKABLE QString env(const QString& name) const;

  // Where `black-bag` actually is. Checked in the places cargo and the
  // distribution packages put one, then on PATH. Empty means absent, which is
  // an ordinary state on a machine that has not installed the engine yet.
  Q_INVOKABLE QString locateEngine() const;

  Q_INVOKABLE bool fileExists(const QString& path) const;

  // Used only for text the operator asked to have on the clipboard and which
  // is not itself a secret -- a username, a URL, a record title. Secret bytes
  // never come through here: the deck routes those through
  // `black-bag agent copy --to clipboard`, so the plaintext is written by the
  // engine and cleared by the engine on its own timer, and this process never
  // sees it.
  Q_INVOKABLE void copyToClipboard(const QString& text) const;

  // Open a URL in whatever the desktop registered. Used for a record's stored
  // site address, and refuses anything that is not http(s) -- a vault entry is
  // attacker-influenced data, and handing an arbitrary scheme to xdg-open is
  // how a stored `file://` or `ssh://` turns a click into an execution.
  Q_INVOKABLE bool openExternal(const QString& url) const;

  [[nodiscard]] QVariantMap settings() const { return mSettings; }
  Q_INVOKABLE void setSetting(const QString& key, const QVariant& value);
  Q_INVOKABLE void reloadSettings();

  [[nodiscard]] QVariantMap palette() const { return mPalette; }
  Q_INVOKABLE void reloadPalette();

  // Window geometry, remembered between runs. Stored beside the settings so
  // there is one file to delete to get a clean slate.
  Q_INVOKABLE void rememberGeometry(int width, int height, bool maximized);

signals:
  void settingsChanged();
  void paletteChanged();
  void raiseRequested();

private:
  void loadSettings();
  void writeSettings();
  void rewatchSettings();

  QFileSystemWatcher mWatcher;
  QVariantMap mSettings;
  QVariantMap mPalette;
};
