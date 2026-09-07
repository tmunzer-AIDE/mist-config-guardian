"""Tests for the authenticator provisioning QR code."""

import re

import segno

from mist_config_guardian_backend.security.totp import totp_provisioning_uri, totp_qr_svg

SECRET = "JBSWY3DPEHPK3PXP"
ACCOUNT = "s.kaur@northwind.example"
ISSUER = "Mist Config Guardian"


def _uri() -> str:
    return totp_provisioning_uri(SECRET, account_name=ACCOUNT, issuer=ISSUER)


def _modules_from_svg(svg: str, size: int) -> list[list[bool]]:
    """Rebuild the module grid from the rendered SVG path data.

    Reading the drawing back is what makes this a real test of the rendering
    rather than of the encoder: an authenticator scans the pixels, not the
    library's in-memory matrix.
    """
    match = re.search(r'<path[^>]*\sd="([^"]+)"', svg)
    assert match is not None, "the rendered SVG has no path data"
    commands = match.group(1)

    grid = [[False] * size for _ in range(size)]
    x = y = 0
    # segno emits absolute "M x y.5" moves and relative "m dx dy" hops, each
    # followed by horizontal runs "h n" that paint n consecutive dark modules.
    for token in re.findall(r"[Mmh]-?[\d.]+(?:[ ,]-?[\d.]+)?", commands):
        kind, _, rest = token[0], token[1], token[1:]
        numbers = [float(value) for value in re.split(r"[ ,]", rest.strip()) if value]
        if kind == "M":
            x, y = int(numbers[0]), int(numbers[1])
        elif kind == "m":
            x, y = x + int(numbers[0]), y + int(numbers[1])
        else:
            run = int(numbers[0])
            for offset in range(run):
                grid[y][x + offset] = True
            x += run
    return grid


def test_provisioning_uri_carries_the_secret_issuer_and_account() -> None:
    """An authenticator needs all three to label and compute the code."""
    uri = _uri()

    assert uri.startswith("otpauth://totp/")
    assert f"secret={SECRET}" in uri
    assert "issuer=Mist%20Config%20Guardian" in uri
    assert "s.kaur%40northwind.example" in uri


def test_rendered_svg_reproduces_the_encoders_module_grid() -> None:
    """The drawing matches the encoder module for module.

    A QR an authenticator cannot read is worse than none at all, and a rendering
    bug would not be visible in a UI review, so the pixels are compared against
    the encoder's own matrix rather than eyeballed.
    """
    uri = _uri()
    expected = [list(row) for row in segno.make(uri, error="m").matrix]
    size = len(expected)

    svg = totp_qr_svg(uri)
    border = 2
    view_box_match = re.search(r'viewBox="([^"]+)"', svg)
    assert view_box_match is not None
    view_box = [int(value) for value in view_box_match.group(1).split()]
    assert view_box == [0, 0, size + 2 * border, size + 2 * border]

    drawn = _modules_from_svg(svg, size + 2 * border)
    for row_index, row in enumerate(expected):
        for column_index, module in enumerate(row):
            assert drawn[row_index + border][column_index + border] == bool(module), (
                f"module ({row_index}, {column_index}) does not match the encoder"
            )


def test_svg_is_self_contained_and_scalable() -> None:
    """The page inlines this markup, so it must carry no external reference."""
    svg = totp_qr_svg(_uri())

    assert svg.startswith("<svg")
    assert "viewBox" in svg
    # No fixed width or height, so the page controls the displayed size.
    assert 'width="' not in svg
    assert 'height="' not in svg
    assert "<?xml" not in svg
    assert "http://" not in svg.replace('xmlns="http://www.w3.org/2000/svg"', "")


def test_a_quiet_zone_surrounds_the_symbol() -> None:
    """Scanners need the mandated light border; without it many fail to lock on."""
    uri = _uri()
    size = len(segno.make(uri, error="m").matrix)
    drawn = _modules_from_svg(totp_qr_svg(uri), size + 4)

    for index in range(size + 4):
        assert not drawn[0][index]
        assert not drawn[1][index]
        assert not drawn[-1][index]
        assert not drawn[-2][index]
        assert not drawn[index][0]
        assert not drawn[index][1]
        assert not drawn[index][-1]
        assert not drawn[index][-2]
