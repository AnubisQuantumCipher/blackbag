#include "datastream.hpp"

void StdioCollector::setWaitForEnd(bool value) {
  if (mWaitForEnd == value) return;
  mWaitForEnd = value;
  emit waitForEndChanged();
}

void StdioCollector::feed(const QString& chunk) {
  if (chunk.isEmpty()) return;
  mText += chunk;
  emit textChanged();
}

void StdioCollector::finish() { emit streamFinished(); }

void SplitParser::setSplitMarker(const QString& marker) {
  if (mMarker == marker) return;
  mMarker = marker;
  emit splitMarkerChanged();
}

void SplitParser::feed(const QString& chunk) {
  if (mMarker.isEmpty()) {
    // No marker means no way to know where a record ends. Emitting the raw
    // chunk would hand the consumer a fragment cut at an arbitrary pipe
    // boundary, so hold it instead and let finish() release the whole thing.
    mBuffer += chunk;
    return;
  }

  mBuffer += chunk;

  qsizetype at = 0;
  while (true) {
    const qsizetype hit = mBuffer.indexOf(mMarker, at);
    if (hit < 0) break;
    const QString record = mBuffer.sliced(at, hit - at);
    at = hit + mMarker.length();
    if (!record.isEmpty()) emit read(record);
  }
  if (at > 0) mBuffer = mBuffer.sliced(at);
}

void SplitParser::finish() {
  // A final record with no trailing marker is still a record. Dropping it
  // would lose the last line of a stream that ended without a newline.
  if (!mBuffer.isEmpty()) {
    const QString tail = mBuffer;
    mBuffer.clear();
    emit read(tail);
  }
}

// The buffer routinely holds a revealed secret between runs, so it is
// overwritten before it is released rather than merely detached.
void StdioCollector::reset() {
  if (!mText.isEmpty()) {
    mText.fill(u'\0');
    mText.clear();
    emit textChanged();
  }
}

void SplitParser::reset() {
  if (!mBuffer.isEmpty()) {
    mBuffer.fill(u'\0');
    mBuffer.clear();
  }
}
