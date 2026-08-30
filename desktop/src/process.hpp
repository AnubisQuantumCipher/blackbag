// An asynchronous child process, API-compatible with Quickshell.Io's Process.
//
// The deck never blocks on the engine. Every `black-bag` invocation is one of
// these: the command is assigned, `running` is set true, and the answer
// arrives later through a stream sink and the `exited` signal. The unlock can be
// grinding through Argon2 and the surface still repaints.
//
// This type spawns and reports. It does not know what `black-bag` is, does not
// parse its output, and never decides that a command succeeded -- the exit
// code and the bytes go to QML exactly as the OS produced them.
#pragma once

// glibc defines these as macros, which would otherwise mangle the property
// names the QML was written against. The QML says `stdout:` and `stderr:`, so
// that is what has to reach moc.
#ifdef stdout
#undef stdout
#endif
#ifdef stderr
#undef stderr
#endif

#include <QObject>
#include <QProcess>
#include <QStringDecoder>
#include <QStringList>
#include <QtQml/qqmlregistration.h>

#include "datastream.hpp"

class Process : public QObject {
  Q_OBJECT
  QML_ELEMENT

  Q_PROPERTY(QStringList command READ command WRITE setCommand NOTIFY commandChanged)
  Q_PROPERTY(bool running READ running WRITE setRunning NOTIFY runningChanged)
  Q_PROPERTY(DataStream* stdout READ stdoutSink WRITE setStdoutSink NOTIFY stdoutSinkChanged)
  Q_PROPERTY(DataStream* stderr READ stderrSink WRITE setStderrSink NOTIFY stderrSinkChanged)
  Q_PROPERTY(int processId READ processId NOTIFY runningChanged)
  Q_PROPERTY(bool stdinEnabled READ stdinEnabled WRITE setStdinEnabled NOTIFY stdinEnabledChanged)

public:
  explicit Process(QObject* parent = nullptr);
  ~Process() override;

  [[nodiscard]] QStringList command() const { return mCommand; }
  void setCommand(const QStringList& command);

  [[nodiscard]] bool running() const { return mRunning; }
  void setRunning(bool running);

  [[nodiscard]] DataStream* stdoutSink() const { return mStdout; }
  void setStdoutSink(DataStream* sink);

  [[nodiscard]] DataStream* stderrSink() const { return mStderr; }
  void setStderrSink(DataStream* sink);

  [[nodiscard]] int processId() const;

  [[nodiscard]] bool stdinEnabled() const { return mStdinEnabled; }
  void setStdinEnabled(bool enabled);

  // Write to the child's standard input. This is the only channel a
  // passphrase is ever allowed to take: an argument vector is readable by any
  // process on the machine through /proc/<pid>/cmdline, and an environment
  // variable is readable by the child's own descendants. Setting
  // `stdinEnabled` back to false closes the pipe, which is what tells the
  // engine the passphrase is complete.
  Q_INVOKABLE void write(const QString& data);

  // Deliver a POSIX signal to the child. The vault uses SIGTERM to abort a
  // running encrypt or decrypt; the engine's own cleanup decides what a
  // half-written output becomes.
  Q_INVOKABLE void signal(int signum);

signals:
  void commandChanged();
  void runningChanged();
  void stdoutSinkChanged();
  void stderrSinkChanged();
  void stdinEnabledChanged();
  void started();
  void exited(int exitCode, int exitStatus);

private:
  void start();
  void stop();
  void drain(QProcess::ProcessChannel channel);
  void onFinished(int exitCode, QProcess::ExitStatus status);
  void onFailed(QProcess::ProcessError error);
  void settle(int exitCode, int exitStatus);

  QProcess* mProc = nullptr;
  QStringList mCommand;
  DataStream* mStdout = nullptr;
  DataStream* mStderr = nullptr;
  QStringDecoder mOutDecoder{QStringDecoder::Utf8};
  QStringDecoder mErrDecoder{QStringDecoder::Utf8};
  bool mStdinEnabled = false;
  bool mRunning = false;
  bool mSettled = false;
};
