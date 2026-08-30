// BLACK-BAG — the credential command deck as a standalone desktop application.
//
// This program is a renderer and a process driver. It holds no key material,
// derives no key, performs no cryptography, and reaches no verdict of its own:
// every posture on screen is the `black-bag` engine's own JSON, carried
// through verbatim. When the engine declines to state something, the deck
// draws UNKNOWN rather than filling in a pass.
//
// Three rules govern the whole surface and are worth stating at the entry
// point, because every later file assumes them:
//
//   1. No secret is stored here. Record metadata comes from the agent; secret
//      bytes are fetched only on an explicit COPY or SHOW, and a SHOW clears
//      itself on a visible countdown.
//   2. A passphrase crosses to the engine on stdin and never in an argument
//      vector. /proc/<pid>/cmdline is world-readable.
//   3. Unknown is drawn as UNKNOWN. A stale status desaturates rather than
//      asserting a posture it cannot vouch for.
//
// A second launch hands itself to the running instance and exits, so a
// launcher entry pressed twice does not end up with two decks polling one
// agent and racing each other's reveal countdowns.

#include <QCommandLineParser>
#include <QGuiApplication>
#include <QIcon>
#include <QLocalServer>
#include <QLocalSocket>
#include <QQmlApplicationEngine>
#include <QQmlError>
#include <QQuickStyle>

#include <unistd.h>
#include <cstdio>

#include "app.hpp"

namespace {

// Per-user, so two people on one machine each get their own deck rather than
// one silently steering the other's.
QString socketName() {
  return QStringLiteral("blackbag-desktop-%1").arg(::getuid());
}

// Ask the instance that is already running to come forward. Returns false when
// there is nothing listening, which is the ordinary first-launch case.
bool raiseRunningInstance() {
  QLocalSocket socket;
  socket.connectToServer(socketName());
  if (!socket.waitForConnected(300)) return false;
  socket.write("raise");
  socket.flush();
  socket.waitForBytesWritten(300);
  socket.disconnectFromServer();
  return true;
}

} // namespace

int main(int argc, char* argv[]) {
  QGuiApplication::setApplicationName(QStringLiteral("Black-Bag"));
  QGuiApplication::setApplicationVersion(QStringLiteral(BLACKBAG_DESKTOP_VERSION));
  QGuiApplication::setOrganizationName(QStringLiteral("Khephri Labs"));
  QGuiApplication::setDesktopFileName(QStringLiteral("dev.blackbag.Deck"));

  QGuiApplication app(argc, argv);

  QCommandLineParser parser;
  parser.setApplicationDescription(
    QStringLiteral("Credential command deck. Drives the `black-bag` engine; "
                   "performs no cryptography itself and stores no secret."));
  parser.addHelpOption();
  parser.addVersionOption();
  parser.process(app);

  if (raiseRunningInstance()) return 0;

  // Nothing was listening, so this process becomes the instance. A stale
  // socket from a crashed run would otherwise block the listen forever.
  QLocalServer::removeServer(socketName());
  QLocalServer server;
  server.setSocketOptions(QLocalServer::UserAccessOption);
  if (!server.listen(socketName()))
    fprintf(stderr, "blackbag-desktop: single-instance socket unavailable; "
                    "a second launch will open its own window\n");

  QQuickStyle::setStyle(QStringLiteral("Basic"));
  QGuiApplication::setWindowIcon(QIcon(QStringLiteral(":/icons/black-bag.svg")));

  QQmlApplicationEngine engine;

  // Written straight to stderr rather than through the logging categories,
  // which a distribution's logging rules can and do switch off. A program that
  // cannot build its own window has to be able to say so unconditionally --
  // exiting silently is the one outcome that leaves nothing to act on.
  QObject::connect(&engine, &QQmlApplicationEngine::warnings, &app,
                   [](const QList<QQmlError>& warnings) {
                     for (const QQmlError& warning : warnings)
                       fprintf(stderr, "blackbag-desktop: %s\n",
                               warning.toString().toUtf8().constData());
                   });
  QObject::connect(&engine, &QQmlApplicationEngine::objectCreationFailed, &app,
                   [](const QUrl& url) {
                     fprintf(stderr, "blackbag-desktop: could not create %s\n",
                             url.toString().toUtf8().constData());
                   });

  engine.loadFromModule("BlackBag", "Main");
  if (engine.rootObjects().isEmpty()) {
    fprintf(stderr, "blackbag-desktop: the window could not be built\n");
    return 1;
  }

  QObject::connect(&server, &QLocalServer::newConnection, &app, [&server] {
    auto* socket = server.nextPendingConnection();
    if (!socket) return;
    QObject::connect(socket, &QLocalSocket::readyRead, socket, [socket] {
      socket->readAll();
      if (auto* instance = App::instance()) emit instance->raiseRequested();
    });
    QObject::connect(socket, &QLocalSocket::disconnected, socket,
                     &QLocalSocket::deleteLater);
  });

  return app.exec();
}
