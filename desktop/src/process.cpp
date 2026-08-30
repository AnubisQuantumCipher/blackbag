#include "process.hpp"

#include <QDebug>
#include <QTimer>

#include <csignal>
#include <cstdio>

Process::Process(QObject* parent) : QObject(parent) {}

Process::~Process() {
  if (mProc) {
    mProc->disconnect(this);
    if (mProc->state() != QProcess::NotRunning) {
      mProc->terminate();
      if (!mProc->waitForFinished(500)) mProc->kill();
    }
  }
}

void Process::setCommand(const QStringList& command) {
  if (mCommand == command) return;
  mCommand = command;
  emit commandChanged();
}

void Process::setStdoutSink(DataStream* sink) {
  if (mStdout == sink) return;
  mStdout = sink;
  emit stdoutSinkChanged();
}

void Process::setStderrSink(DataStream* sink) {
  if (mStderr == sink) return;
  mStderr = sink;
  emit stderrSinkChanged();
}

int Process::processId() const {
  return mProc ? static_cast<int>(mProc->processId()) : 0;
}

void Process::setRunning(bool running) {
  if (running == mRunning) return;
  if (running) start();
  else stop();
}

void Process::start() {
  if (mCommand.isEmpty()) {
    qWarning() << "blackbag-desktop: refusing to start a process with no command";
    return;
  }

  // A fresh QProcess per run. Reusing one would carry the previous run's
  // buffered bytes and exit state into this one, which is exactly the sort of
  // stale-state bleed the deck's honesty rules exist to prevent.
  if (mProc) {
    mProc->disconnect(this);
    mProc->deleteLater();
  }
  mProc = new QProcess(this);
  mProc->setProcessChannelMode(QProcess::SeparateChannels);

  mOutDecoder = QStringDecoder(QStringDecoder::Utf8);
  mErrDecoder = QStringDecoder(QStringDecoder::Utf8);
  mSettled = false;

  // Each run starts with empty sinks, exactly as Quickshell's do. Skipping
  // this is how "the record list broke after the first refresh" happens: the
  // second run's JSON lands appended to the first run's, and the parse throws.
  if (mStdout) mStdout->reset();
  if (mStderr) mStderr->reset();

  connect(mProc, &QProcess::readyReadStandardOutput, this,
          [this] { drain(QProcess::StandardOutput); });
  connect(mProc, &QProcess::readyReadStandardError, this,
          [this] { drain(QProcess::StandardError); });
  connect(mProc, &QProcess::finished, this, &Process::onFinished);
  connect(mProc, &QProcess::errorOccurred, this, &Process::onFailed);

  const QString program = mCommand.first();
  const QStringList arguments = mCommand.mid(1);

  mRunning = true;
  emit runningChanged();

  mProc->start(program, arguments);
  emit started();

  // `started` is where QML writes a passphrase, so the decision to close is
  // made after that handler has run. A child that is never written to must
  // still see EOF, or a command that reads stdin at all hangs.
  if (!mStdinEnabled && mProc->state() != QProcess::NotRunning)
    mProc->closeWriteChannel();
}

void Process::stop() {
  if (!mProc || mProc->state() == QProcess::NotRunning) {
    if (mRunning) {
      mRunning = false;
      emit runningChanged();
    }
    return;
  }

  auto* proc = mProc;
  proc->terminate();
  // Escalate only if the child ignores SIGTERM. A cooperative engine gets the
  // chance to finish its own teardown before it is taken apart.
  QTimer::singleShot(1500, proc, [proc] {
    if (proc->state() != QProcess::NotRunning) proc->kill();
  });
}

void Process::setStdinEnabled(bool enabled) {
  if (mStdinEnabled == enabled) return;
  mStdinEnabled = enabled;
  // Closing is the meaningful direction: an engine reading a passphrase waits
  // on EOF, so a pipe left open is an unlock that never returns.
  if (!enabled && mProc && mProc->state() != QProcess::NotRunning)
    mProc->closeWriteChannel();
  emit stdinEnabledChanged();
}

// Written and flushed synchronously. The bytes are handed to the pipe and not
// kept: this object holds no copy of what went through it, so nothing here
// survives into a later core dump or a later read of this process's heap.
void Process::write(const QString& data) {
  if (!mProc || mProc->state() == QProcess::NotRunning) {
    fprintf(stderr, "blackbag-desktop: write to a process that is not running\n");
    return;
  }
  QByteArray bytes = data.toUtf8();
  mProc->write(bytes);
  mProc->waitForBytesWritten(1000);
  bytes.fill('\0');
}

void Process::signal(int signum) {
  if (!mProc) return;
  const auto pid = mProc->processId();
  if (pid <= 0) return;
  ::kill(static_cast<pid_t>(pid), signum);
}

void Process::drain(QProcess::ProcessChannel channel) {
  if (!mProc) return;

  const bool isOut = channel == QProcess::StandardOutput;
  DataStream* sink = isOut ? mStdout : mStderr;
  const QByteArray raw = isOut ? mProc->readAllStandardOutput()
                               : mProc->readAllStandardError();
  if (raw.isEmpty()) return;

  // Decoded incrementally: a pipe read can land mid-codepoint, and a naive
  // per-chunk fromUtf8 would turn a split multi-byte character into two
  // replacement characters inside an otherwise valid JSON line.
  const QString text = isOut ? mOutDecoder.decode(raw) : mErrDecoder.decode(raw);
  if (sink && !text.isEmpty()) sink->feed(text);
}

void Process::onFinished(int exitCode, QProcess::ExitStatus status) {
  settle(exitCode, status == QProcess::NormalExit ? 0 : 1);
}

void Process::onFailed(QProcess::ProcessError error) {
  if (error != QProcess::FailedToStart) return;
  // The shell's convention for "could not execute". The vault already reads
  // 127 as exactly that, so a binary that vanished between the probe and the
  // call surfaces as a refusal rather than as silence.
  settle(127, 1);
}

void Process::settle(int exitCode, int exitStatus) {
  if (mSettled) return;
  mSettled = true;

  if (mProc) {
    drain(QProcess::StandardOutput);
    drain(QProcess::StandardError);
  }

  // Streams close before the exit is announced, because the QML handler for
  // `exited` reads what those streams collected.
  if (mStdout) mStdout->finish();
  if (mStderr) mStderr->finish();

  if (mRunning) {
    mRunning = false;
    emit runningChanged();
  }

  emit exited(exitCode, exitStatus);
}
