from nebula_api.dns_profiles import effective_profile, resolvers_for


def test_default_is_the_deployments_own_resolver() -> None:
    assert resolvers_for("default", "198.18.0.53") == ["198.18.0.53"]


def test_default_with_no_resolver_leaves_the_app_its_own() -> None:
    assert resolvers_for("default", "") == []


def test_filtering_profiles_use_adguard() -> None:
    assert resolvers_for("ads", "198.18.0.53") == ["94.140.14.14", "94.140.15.15"]
    assert resolvers_for("family", "") == ["94.140.14.15", "94.140.15.16"]


def test_a_device_overrides_its_account_and_null_follows_it() -> None:
    assert effective_profile("default", "family") == "family"
    assert effective_profile("ads", None) == "ads"
