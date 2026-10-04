"""
Pruebas de punta a punta: servidor real + Microsoft Edge (Playwright).

Levantan uvicorn en un puerto libre con DEMO_MODE=true y recorren la app como
un usuario: login con 2FA y términos, subir y arrastrar canciones, reproducir,
buscar, crear playlists con portada, registrar cuentas y cerrar la pestaña.

    pytest -m e2e                      # Edge instalado (por defecto)
    E2E_BROWSER_CHANNEL=chrome pytest -m e2e
    E2E_HEADED=1 pytest -m e2e         # ver el navegador
"""

import os
import secrets
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

from tests.conftest import make_mp3, make_png

pytestmark = pytest.mark.e2e
ROOT = Path(__file__).resolve().parents[2]
playwright_api = pytest.importorskip("playwright.sync_api")


# ------------------------------------------------------------ servidor y navegador
def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def base_url():
    port = _free_port()
    env = {**os.environ, "DEMO_MODE": "true", "SCAN_ON_STARTUP": "false", "PBKDF2_ITERATIONS": "100000",
           "MONGO_URI": "", "JWT_SECRET_KEY": secrets.token_hex(32), "PYTHONUTF8": "1"}
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            urllib.request.urlopen(url + "/health", timeout=1)
            break
        except OSError:
            time.sleep(0.2)
    else:
        proc.kill()
        pytest.fail("El servidor no arrancó")
    yield url
    proc.terminate()
    proc.wait(timeout=10)


@pytest.fixture(scope="module")
def browser():
    with playwright_api.sync_playwright() as p:
        try:
            b = p.chromium.launch(channel=os.getenv("E2E_BROWSER_CHANNEL", "msedge"),
                                  headless=not os.getenv("E2E_HEADED"))
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"No hay navegador disponible para E2E: {exc}")
        yield b
        b.close()


@pytest.fixture
def context(browser):
    ctx = browser.new_context(viewport={"width": 1280, "height": 860}, locale="es-CO")
    yield ctx
    ctx.close()


@pytest.fixture
def page(context, base_url):
    pg = context.new_page()
    pg.set_default_timeout(10_000)
    pg.goto(base_url)
    return pg


# ------------------------------------------------------------ utilidades
def mp3_file(name: str) -> dict:
    return {"name": name, "mimeType": "audio/mpeg", "buffer": make_mp3(120)}


def login_demo(page) -> None:
    page.fill("#login-user", "demo")
    page.fill("#login-pass", "demo123")
    page.click("#form-login button[type=submit]")
    page.wait_for_selector("#m-mfa:not(.hidden)")
    page.fill("#mfa-code", "123456")  # 6 dígitos: se envía solo
    page.wait_for_selector("#m-terms:not(.hidden), #app:not(.hidden)")
    if page.is_visible("#m-terms"):
        page.click(".capsule")
        page.click("#terms-accept")
    page.wait_for_selector("#app:not(.hidden)")


def upload(page, *names) -> int:
    before = page.locator("#queue .track").count()
    page.set_input_files("#file-input", [mp3_file(n) for n in names])
    page.wait_for_function(f"document.querySelectorAll('#queue .track').length >= {before + len(names)}")
    return before + len(names)


# ------------------------------------------------------------ pruebas
def test_login_2fa_inline_error_and_terms(page):
    page.fill("#login-user", "demo")
    page.fill("#login-pass", "contraseña-mala1")
    page.click("#form-login button[type=submit]")
    page.wait_for_selector("#login-error:has-text('incorrectos')")

    page.fill("#login-pass", "demo123")
    page.click("#form-login button[type=submit]")
    page.wait_for_selector("#m-mfa:not(.hidden)")
    page.fill("#mfa-code", "111111")
    page.wait_for_selector("#mfa-error:has-text('incorrecto')")
    page.fill("#mfa-code", "123456")

    page.wait_for_selector("#m-terms:not(.hidden)")
    assert page.is_disabled("#terms-accept")              # rechazar términos: botón deshabilitado
    page.click(".capsule")
    assert page.is_enabled("#terms-accept")
    page.click("#terms-accept")

    page.wait_for_selector("#app:not(.hidden)")
    assert "Sube tus canciones aquí" in page.inner_text("#dropzone")
    assert "disabled" in page.get_attribute("#player", "class")
    assert page.is_disabled("#play")


def test_upload_play_next_and_pointers(page):
    login_demo(page)
    upload(page, "Queen - Bohemian Rhapsody.mp3", "Shakira - Ojos Así.mp3")
    assert page.is_enabled("#play")
    page.click("#play")
    page.wait_for_function("!document.getElementById('audio').paused")
    page.click("#next")
    page.wait_for_function("document.getElementById('ptr-prev').textContent !== '—'")
    assert page.inner_text("#now-title") != ""


def test_drag_and_drop_from_file_explorer(page):
    login_demo(page)
    before = page.locator("#queue .track").count()
    dragging = page.evaluate("""() => {
        const frames = 40, size = 417, buf = new Uint8Array(frames * size);
        for (let f = 0; f < frames; f++) buf.set([0xFF, 0xFB, 0x90, 0x64], f * size);
        const dt = new DataTransfer();
        ["Bomba Estéreo - Soy Yo.mp3", "Carlos Vives - La Bicicleta.mp3"].forEach(n => dt.items.add(new File([buf], n, { type: "audio/mpeg" })));
        window.dispatchEvent(new DragEvent("dragenter", { dataTransfer: dt, bubbles: true }));
        const green = document.body.classList.contains("dragging");
        window.__dt = dt;
        return green;
    }""")
    assert dragging, "la zona de carga no se marcó al arrastrar"
    page.evaluate("window.dispatchEvent(new DragEvent('drop', { dataTransfer: window.__dt, bubbles: true, cancelable: true }))")
    page.wait_for_function(f"document.querySelectorAll('#queue .track').length >= {before + 2}")
    assert not page.evaluate("document.body.classList.contains('dragging')")


def test_create_playlist_with_cover_thumbnail(page):
    login_demo(page)
    queued = upload(page, "Juanes - La Camisa Negra.mp3")
    page.click("#nav-new-playlist")
    page.fill("#pl-new-name", "Viaje a Nariño")
    page.set_input_files("#new-cover-input", {"name": "portada.png", "mimeType": "image/png", "buffer": make_png(64, 64)})
    page.wait_for_function("document.querySelector('#new-cover-thumb img')?.complete")
    page.check("#pl-from-queue")
    page.click("#form-playlist button[type=submit]")

    page.wait_for_selector("#playlist-panel:not(.hidden)")
    assert page.inner_text("#pl-name") == "Viaje a Nariño"
    # Portada grande en la vista y miniatura en el apartado de playlists
    page.wait_for_function("document.querySelector('#pl-cover .thumb.lg img')?.naturalWidth > 0")
    page.wait_for_function("[...document.querySelectorAll('#playlist-nav .thumb.sm img')].some(i => i.naturalWidth > 0)")
    assert page.locator("#pl-tracks .track").count() == queued
    assert "Viaje a Nariño" in page.inner_text("#playlist-nav")

    page.click("#pl-play")
    page.wait_for_selector("#queue-panel:not(.hidden)")


def test_add_track_to_playlist_from_queue(page):
    login_demo(page)
    upload(page, "Totó la Momposina - La Candela Viva.mp3")
    page.click("#nav-new-playlist")
    page.fill("#pl-new-name", "Cumbia")
    page.click("#form-playlist button[type=submit]")
    page.wait_for_selector("#playlist-panel:not(.hidden)")
    page.click("#nav-queue")
    last = page.locator("#queue .track").last
    last.hover()
    last.locator(".icon-btn").click()
    page.click("#pl-popover button:has-text('Cumbia')")
    page.wait_for_selector(".toast:has-text('Añadida')")
    page.click("#playlist-nav button:has-text('Cumbia')")
    page.wait_for_selector("#pl-tracks .track:has-text('La Candela Viva')")


def test_interactive_search(page):
    login_demo(page)
    upload(page, "Queen - Don't Stop Me Now.mp3")
    page.fill("#search", "queen")
    page.wait_for_selector("#results:not(.hidden) .result:has-text('Queen')")
    page.fill("#search", "zzzz")
    page.wait_for_selector("#results .empty")


def test_register_any_name_and_same_email_twice(page):
    for name in ("María José Pérez", "Otra Cuenta De María"):
        page.click("#to-register")
        page.fill("#reg-user", name)
        page.fill("#reg-email", "maria@example.com")
        page.fill("#reg-pass", "clave2026x")
        page.click("#form-register button[type=submit]")
        page.wait_for_selector("#m-terms:not(.hidden)")
        page.click(".capsule")
        page.click("#terms-accept")
        page.wait_for_selector("#m-setup:not(.hidden)")
        page.wait_for_function("document.getElementById('setup-qr').naturalWidth > 0")  # QR para Google Authenticator
        page.fill("#setup-code", "123456")
        page.click("#form-setup button[type=submit]")
        page.wait_for_selector("#m-recovery:not(.hidden)")
        assert page.locator("#recovery-codes span").count() == 10
        page.click("#recovery-done")
        page.wait_for_selector("#m-login:not(.hidden)")


def test_session_survives_reload_but_not_closing_the_tab(context, page, base_url):
    login_demo(page)
    page.reload()
    page.wait_for_selector("#app:not(.hidden)")      # misma pestaña: sigue dentro
    page.close()
    fresh = context.new_page()
    fresh.goto(base_url)
    fresh.wait_for_selector("#m-login:not(.hidden)")  # pestaña nueva: hay que iniciar sesión
    assert fresh.is_hidden("#app")


def test_email_banner_and_change_email(page):
    login_demo(page)
    page.wait_for_selector("#email-banner:not(.hidden)")
    assert "demo@zorryfy.test" in page.inner_text("#email-banner-text")
    page.click("#email-change")
    page.fill("#email-new", "demo.nuevo@example.com")
    page.click("#form-email button[type=submit]")
    page.wait_for_selector(".toast:has-text('Email actualizado')")
    assert "demo.nuevo@example.com" in page.inner_text("#email-banner-text")


def test_halloween_decorations_react_to_cursor(page):
    box = page.locator(".deco.pumpkin").first.bounding_box()
    page.mouse.move(box["x"] + box["width"] / 2 + 30, box["y"] + box["height"] / 2)
    page.wait_for_timeout(400)
    transform = page.eval_on_selector(".deco.pumpkin", "el => getComputedStyle(el).transform")
    assert transform != "none"
