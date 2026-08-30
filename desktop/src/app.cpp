#include "app.hpp"

#include <QClipboard>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QDebug>
#include <QGuiApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcessEnvironment>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QUrl>

namespace {

App* gInstance = nullptr;

// The foundational palette, used when no theme file is readable. These are the
// values Omarchy's own shell falls back to, so an unthemed machine gets a
// coherent surface rather than Qt's defaults.
const QVariantMap kFallbackPalette = {
  {QStringLiteral("foreground"), QStringLiteral("#cacccc")},
  {QStringLiteral("background"), QStringLiteral("#101315")},
  {QStringLiteral("accent"), QStringLiteral("#cacccc")},
  {QStringLiteral("urgent"), QStringLiteral("#a55555")},
  {QStringLiteral("muted"), QStringLiteral("#707880")},
};

// A deliberately small reader for the four keys this program needs out of a
// theme's colors.toml. It is not a TOML parser and does not pretend to be: it
// takes top-level `key = "value"` pairs and ignores everything else, so a
// theme that grows a section this program has never heard of is simply not
// read rather than mis-read.
QVariantMap readThemeColors(const QString& path) {
  QFile file(path);
  if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) return {};

  static const QRegularExpression pair(
    QStringLiteral("^\\s*([A-Za-z_][A-Za-z0-9_]*)\\s*=\\s*\"([^\"]*)\"\\s*$"));
  static const QRegularExpression section(QStringLiteral("^\\s*\\["));

  QVariantMap out;
  const QStringList lines = QString::fromUtf8(file.readAll()).split(u'\n');
  for (const QString& line : lines) {
    // Stop at the first table header: anything below it is scoped to that
    // table and its bare keys mean something else.
    if (section.match(line).hasMatch()) break;
    const auto hit = pair.match(line);
    if (!hit.hasMatch()) continue;
    const QString key = hit.captured(1);
    const QString value = hit.captured(2);
    if (!QColor::isValidColorName(value)) continue;
    out.insert(key, value);
  }
  return out;
}

} // namespace

App::App(QObject* parent) : QObject(parent) {
  gInstance = this;
  loadSettings();
  reloadPalette();

  // The settings file is watched, so an edit made in a text editor lands on
  // the surface without a restart. The directory is watched alongside it
  // because this program rewrites the file atomically-ish and an editor may
  // replace the inode outright, which drops a file-only watch.
  const auto onChange = [this] {
    rewatchSettings();
    loadSettings();
    reloadPalette();
  };
  connect(&mWatcher, &QFileSystemWatcher::fileChanged, this, onChange);
  connect(&mWatcher, &QFileSystemWatcher::directoryChanged, this, onChange);
  rewatchSettings();
}

void App::rewatchSettings() {
  const QString path = configPath();
  const QString dir = QFileInfo(path).absolutePath();
  if (QFile::exists(path) && !mWatcher.files().contains(path))
    mWatcher.addPath(path);
  if (QDir(dir).exists() && !mWatcher.directories().contains(dir))
    mWatcher.addPath(dir);
}

App* App::instance() { return gInstance; }

QString App::home() const {
  const QString fromEnv = qEnvironmentVariable("HOME");
  if (!fromEnv.isEmpty()) return fromEnv;
  return QDir::homePath();
}

QString App::configPath() const {
  return home() + QStringLiteral("/.config/black-bag/desktop.json");
}

QString App::appVersion() const {
  return QGuiApplication::applicationVersion();
}

QString App::env(const QString& name) const {
  return qEnvironmentVariable(name.toUtf8().constData());
}

QString App::locateEngine() const {
  // An explicit override wins, so a developer can point the app at a build
  // tree without touching the installed engine.
  const QString override = qEnvironmentVariable("BLACKBAG_ENGINE");
  if (!override.isEmpty() && QFileInfo(override).isExecutable()) return override;

  const QString h = home();
  const QStringList candidates = {
    h + QStringLiteral("/.cargo/bin/black-bag"),
    h + QStringLiteral("/.local/bin/black-bag"),
    QStringLiteral("/usr/local/bin/black-bag"),
    QStringLiteral("/usr/bin/black-bag"),
  };
  for (const QString& candidate : candidates) {
    const QFileInfo info(candidate);
    if (info.isFile() && info.isExecutable()) return candidate;
  }

  const QString onPath = QStandardPaths::findExecutable(QStringLiteral("black-bag"));
  return onPath;
}

bool App::fileExists(const QString& path) const {
  if (path.isEmpty()) return false;
  return QFileInfo::exists(path);
}

// Non-secret text only; see the header. Nothing is retained here, and no
// auto-clear timer is started -- a timer in this process would be a promise
// this process cannot keep across its own exit.
void App::copyToClipboard(const QString& text) const {
  if (text.isEmpty()) return;
  auto* clipboard = QGuiApplication::clipboard();
  if (!clipboard) return;
  clipboard->setText(text, QClipboard::Clipboard);
  if (clipboard->supportsSelection())
    clipboard->setText(text, QClipboard::Selection);
}

void App::loadSettings() {
  QVariantMap loaded;
  QFile file(configPath());
  if (file.open(QIODevice::ReadOnly)) {
    QJsonParseError error{};
    const auto doc = QJsonDocument::fromJson(file.readAll(), &error);
    // A settings file that has been edited into invalid JSON leaves the
    // running values alone rather than resetting the program to defaults
    // mid-session. The next valid save fixes it.
    if (error.error != QJsonParseError::NoError) {
      qWarning().noquote() << "blackbag-desktop: ignoring" << configPath()
                           << "--" << error.errorString();
      return;
    }
    if (doc.isObject()) loaded = doc.object().toVariantMap();
  }

  // Only announce a real change. This is what stops the write -> watcher ->
  // reload path from becoming a loop that repaints the surface forever.
  if (loaded == mSettings) return;
  mSettings = loaded;
  emit settingsChanged();
}

void App::reloadSettings() { loadSettings(); }

void App::writeSettings() {
  const QFileInfo info(configPath());
  QDir().mkpath(info.absolutePath());

  QFile file(configPath());
  if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
    qWarning().noquote() << "blackbag-desktop: cannot write" << configPath()
                         << "--" << file.errorString();
    return;
  }
  const auto doc = QJsonDocument(QJsonObject::fromVariantMap(mSettings));
  file.write(doc.toJson(QJsonDocument::Indented));
  file.close();
  rewatchSettings();
}

void App::setSetting(const QString& key, const QVariant& value) {
  if (key.isEmpty()) return;
  if (mSettings.value(key) == value) return;
  mSettings.insert(key, value);
  writeSettings();
  emit settingsChanged();
  if (key == QStringLiteral("theme")) reloadPalette();
}

void App::rememberGeometry(int width, int height, bool maximized) {
  QVariantMap window;
  window.insert(QStringLiteral("width"), width);
  window.insert(QStringLiteral("height"), height);
  window.insert(QStringLiteral("maximized"), maximized);
  if (mSettings.value(QStringLiteral("window")).toMap() == window) return;
  mSettings.insert(QStringLiteral("window"), window);
  writeSettings();
  emit settingsChanged();
}

void App::reloadPalette() {
  QVariantMap resolved = kFallbackPalette;

  // The desktop theme, when there is one. This program follows whatever the
  // machine is themed to rather than inventing its own colours.
  const QString themeFile =
    home() + QStringLiteral("/.local/state/omarchy/current/theme/colors.toml");
  const QVariantMap themed = readThemeColors(themeFile);
  for (auto it = themed.cbegin(); it != themed.cend(); ++it)
    if (resolved.contains(it.key())) resolved.insert(it.key(), it.value());

  // An explicit override in the settings file beats the theme, because a user
  // who typed a colour meant it.
  const QVariantMap override = mSettings.value(QStringLiteral("theme")).toMap();
  for (auto it = override.cbegin(); it != override.cend(); ++it) {
    if (!resolved.contains(it.key())) continue;
    const QString value = it.value().toString();
    if (QColor::isValidColorName(value)) resolved.insert(it.key(), value);
  }

  if (resolved == mPalette) return;
  mPalette = resolved;
  emit paletteChanged();
}


// A record's site address is data someone else may have chosen. Only http and
// https are handed to the desktop: every other scheme is a way to turn "open
// the site" into "run the handler for whatever this string names", and a
// password manager is precisely where that string is untrusted.
bool App::openExternal(const QString& url) const {
  const QUrl parsed(url, QUrl::StrictMode);
  if (!parsed.isValid() || parsed.host().isEmpty()) return false;
  const QString scheme = parsed.scheme().toLower();
  if (scheme != QStringLiteral("http") && scheme != QStringLiteral("https"))
    return false;
  return QDesktopServices::openUrl(parsed);
}
