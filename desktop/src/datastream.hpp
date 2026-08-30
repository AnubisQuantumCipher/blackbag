// Stdout/stderr sinks, API-compatible with the Quickshell.Io parsers the
// vault QML was written against.
//
// Two shapes, one job each. A StdioCollector buffers the whole stream and
// hands it over once, which is what a command that emits a single JSON object
// wants. A SplitParser emits every completed record the moment it lands, which
// is what a command that streams progress for a gigabyte wants.
//
// Neither one interprets what it carries. They move bytes and say when the
// stream ended; deciding what a line means belongs to the QML that asked for
// the process.
#pragma once

#include <QObject>
#include <QString>
#include <QtQml/qqmlregistration.h>

class DataStream : public QObject {
  Q_OBJECT
  QML_ELEMENT
  QML_UNCREATABLE("DataStream is abstract; use StdioCollector or SplitParser.")

public:
  explicit DataStream(QObject* parent = nullptr) : QObject(parent) {}

  // Called by Process for each chunk the OS handed us. Chunk boundaries are
  // whatever the pipe produced and carry no meaning.
  virtual void feed(const QString& chunk) = 0;

  // Called exactly once, when the stream is at EOF.
  virtual void finish() = 0;
};

class StdioCollector : public DataStream {
  Q_OBJECT
  QML_ELEMENT

  // Present so the QML that sets `waitForEnd: true` keeps working. This
  // collector has no other mode -- it always waits for the end -- so the
  // property is accepted and reported back rather than silently dropped.
  Q_PROPERTY(bool waitForEnd READ waitForEnd WRITE setWaitForEnd NOTIFY waitForEndChanged)
  Q_PROPERTY(QString text READ text NOTIFY textChanged)

public:
  explicit StdioCollector(QObject* parent = nullptr) : DataStream(parent) {}

  [[nodiscard]] bool waitForEnd() const { return mWaitForEnd; }
  void setWaitForEnd(bool value);

  [[nodiscard]] QString text() const { return mText; }

  void feed(const QString& chunk) override;
  void finish() override;

signals:
  void waitForEndChanged();
  void textChanged();
  void streamFinished();

private:
  QString mText;
  bool mWaitForEnd = true;
};

class SplitParser : public DataStream {
  Q_OBJECT
  QML_ELEMENT

  Q_PROPERTY(QString splitMarker READ splitMarker WRITE setSplitMarker NOTIFY splitMarkerChanged)

public:
  explicit SplitParser(QObject* parent = nullptr) : DataStream(parent) {}

  [[nodiscard]] QString splitMarker() const { return mMarker; }
  void setSplitMarker(const QString& marker);

  void feed(const QString& chunk) override;
  void finish() override;

signals:
  void splitMarkerChanged();
  void read(const QString& data);

private:
  QString mBuffer;
  QString mMarker = QStringLiteral("\n");
};
