import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/features/pairing/qr_scan.dart';
import 'package:zxing2/qrcode.dart';

/// [content] as a camera's Y plane would hold it: dark modules at 0, light
/// at 255, [scale] pixels per module, a quiet zone, and rows padded to
/// [stride] bytes the way camera buffers often are.
({Uint8List luma, int size, int stride}) _frame(
  String content, {
  int scale = 6,
  int pad = 24,
}) {
  final QRCode code = Encoder.encode(content, ErrorCorrectionLevel.m);
  final int modules = code.matrix!.width;
  final int size = modules * scale + 2 * 4 * scale;
  final int stride = size + pad;
  final Uint8List luma = Uint8List(stride * size)
    ..fillRange(0, stride * size, 255);
  for (int y = 0; y < modules; y++) {
    for (int x = 0; x < modules; x++) {
      if (code.matrix!.get(x, y) == 1) {
        for (int dy = 0; dy < scale; dy++) {
          for (int dx = 0; dx < scale; dx++) {
            final int px = 4 * scale + x * scale + dx;
            final int py = 4 * scale + y * scale + dy;
            luma[py * stride + px] = 0;
          }
        }
      }
    }
  }
  return (luma: luma, size: size, stride: stride);
}

void main() {
  test('a QR code in a padded camera frame is read', () {
    const String link =
        'nebula://pair?url=https://vpn.example.test:8443&code=ABCD-1234&ca=sha256:00ff';
    final frame = _frame(link);
    expect(decodeQr(frame.luma, frame.size, frame.size, frame.stride), link);
  });

  test('a frame with no code reads as nothing, not an error', () {
    final Uint8List blank = Uint8List(200 * 200)..fillRange(0, 200 * 200, 128);
    expect(decodeQr(blank, 200, 200, 200), isNull);
  });
}
