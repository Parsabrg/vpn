import 'token_pair.dart';
import 'user_principal.dart';

/// The app's authentication state machine. A closed sum type (rather than
/// booleans/flags) so state transitions are assertable directly --
/// `expect(state, isA<AuthSessionExpired>())` -- and so the router redirect
/// and every screen exhaustively `switch` over every possibility.
sealed class AuthState {
  const AuthState();
}

/// Initial state; also entered during app bootstrap (checking stored
/// credentials) and while a sign-in submission is in flight.
class AuthAuthenticating extends AuthState {
  const AuthAuthenticating();
}

/// No valid session: never signed in, or a cold start found no stored
/// refresh token. Distinct from [AuthSessionExpired] -- the sign-in screen
/// shows different copy for each.
class AuthUnauthenticated extends AuthState {
  const AuthUnauthenticated();
}

class AuthAuthenticated extends AuthState {
  const AuthAuthenticated({required this.tokens, this.me});

  final TokenPair tokens;

  /// Populated by a follow-up `/v1/auth/me` call after sign-in/refresh;
  /// null until that resolves. Not calling `/v1/auth/me` is never treated
  /// as a reason to leave the authenticated state -- it only affects what
  /// the account screen can render.
  final UserPrincipal? me;

  AuthAuthenticated copyWith({TokenPair? tokens, UserPrincipal? me}) {
    return AuthAuthenticated(tokens: tokens ?? this.tokens, me: me ?? this.me);
  }
}

/// A previously authenticated session was revoked -- refresh-token reuse
/// was detected server-side, or refresh otherwise failed after a session
/// existed. Distinct from [AuthUnauthenticated] so the sign-in screen can
/// say "your session ended, please sign in again" rather than a plain
/// "please sign in."
class AuthSessionExpired extends AuthState {
  const AuthSessionExpired();
}
