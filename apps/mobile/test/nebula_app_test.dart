import 'package:flutter_test/flutter_test.dart';
import 'package:nebula_mobile/src/nebula_app.dart';

void main() {
  testWidgets('identifies the scaffold without claiming VPN functionality', (
    WidgetTester tester,
  ) async {
    await tester.pumpWidget(const NebulaApp());

    expect(find.text('Nebula VPN'), findsOneWidget);
    expect(find.text('Client workspace ready'), findsOneWidget);
    expect(
      find.text('Authentication and VPN connectivity are not implemented yet.'),
      findsOneWidget,
    );
  });
}
