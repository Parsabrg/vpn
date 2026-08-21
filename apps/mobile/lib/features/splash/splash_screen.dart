import 'package:flutter/material.dart';

/// Purely presentational. `AuthNotifier.bootstrap()` runs once from
/// `main.dart` before the app is even built (see there for why), and the
/// router's redirect moves away from this screen automatically once
/// [AuthState] resolves to authenticated or unauthenticated -- this widget
/// never has to drive navigation itself.
class SplashScreen extends StatelessWidget {
  const SplashScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: Semantics(
          label: 'Loading Nebula VPN',
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: <Widget>[
              Icon(
                Icons.shield_outlined,
                size: 56,
                color: Theme.of(context).colorScheme.primary,
              ),
              const SizedBox(height: 24),
              const CircularProgressIndicator(),
            ],
          ),
        ),
      ),
    );
  }
}
