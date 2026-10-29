from shop.auth import check_password


def test_check_password():
    assert not check_password("x", "y")
