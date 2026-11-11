"""Brazilian IP pack: Câmara LEGIN adapter (LPI), INPI Manual de Marcas
adapter, and the LPI / Manual citation forms. No network: fetch is patched
with HTML fixtures shaped like the real pages."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_donna import DonnaCase  # noqa: E402
import donna  # noqa: E402

CAMARA = """<html><head><title>x</title></head><body>
<p>LEI Nº 9.279, DE 14 DE MAIO DE 1996</p>
<h1>DISPOSIÇÕES PRELIMINARES</h1>
<p><font>Art. 1º Esta Lei regula
direitos e obrigações relativos à propriedade industrial. </font></p>
<p>Art. 40. A patente de invenção vigorará pelo prazo de 20 (vinte) anos.</p>
<p>Parágrafo único. (Revogado pela Lei nº 14.195, de 26/8/2021)</p>
<p align="center">CAPÍTULO IX</p><p align="center">DO EXAME</p>
<p>Art. 158. Protocolizado, o
pedido será publicado para apresentação de oposição no prazo de
60 (sessenta) dias. </p>
<p>§ 1º O depositante será intimado da oposição, podendo se manifestar no
prazo de 60 (sessenta) dias. </p>
<p>Brasília, 14 de maio de 1996; 175º da Independência e 108º da República.</p>
</body></html>""".encode()

def manual_page(body):
    return ('<html><div class="wiki wiki-page">' + body +
            '</div><div style="clear:both"></div><div id="footer">f</div></html>').encode()

MANUAL = {
    "/projects/manual/wiki": manual_page(
        '<a href="/projects/manual/wiki/05_Exame_substantivo">5</a>'),
    "/projects/manual/wiki/05_Exame_substantivo": manual_page(
        '<h2>5. Exame substantivo<a href="#5" class="wiki-anchor">&para;</a></h2>'
        '<p>Intro do capítulo.</p>'
        '<h3>5.12 Análise de pedidos com oposição</h3><p>Resumo.</p>'
        '<a href="/projects/manual/wiki/5%C2%B712_An%C3%A1lise_de_pedidos_com_oposi%C3%A7%C3%A3o">x</a>'),
    "/projects/manual/wiki/5·12_Análise_de_pedidos_com_oposição": manual_page(
        '<h2>5.12 Análise de pedidos com oposição</h2>'
        '<p>Já a manifestação à oposição é o instrumento de defesa do requerente.</p>'
        '<h3>5.12.1 Orientações gerais</h3><h4>Exigências para a opoente</h4>'
        '<p>Cabe à impugnante apresentar seus argumentos.</p>'
        '<table><tr><td>A</td><td>B</td></tr></table><img src="x.png">'),
}

def fake_fetch(url, ua=None):
    if "camara.leg.br" in url:
        return CAMARA
    import urllib.parse
    path = urllib.parse.unquote(url.replace(donna.INPI_MANUAL_BASE, ""))
    return MANUAL[path]

LPI = "br/1996/lei/9279@consolidated:pt-BR"
MAN = "br/2022/inpi-manual/marcas@consolidated:pt-BR"

class TestBrazilIP(DonnaCase):
    def setUp(self):
        super().setUp()
        p = mock.patch.object(donna, "fetch", side_effect=fake_fetch)
        p.start()
        self.addCleanup(p.stop)
        donna.WORKS[("br", "2022", "inpi-manual", "marcas")]["delay"] = 0
        donna.ingest(self.con, "br/1996/lei/9279")
        donna.ingest(self.con, "br/2022/inpi-manual/marcas")

    def frag(self, fid):
        return self.con.execute("SELECT heading, text FROM fragments WHERE id = ?",
                                (fid,)).fetchone()

    def test_lpi_articles_unwrapped_and_signature_cut(self):
        h, t = self.frag(LPI + "#art-158")
        self.assertIn("publicado para apresentação de oposição no prazo de 60", t)
        self.assertNotIn("Brasília", t)
        self.assertEqual(h, "CAPÍTULO IX - DO EXAME")

    def test_structural_heading_moved_out_of_previous_article(self):
        _, t = self.frag(LPI + "#art-40")
        self.assertNotIn("CAPÍTULO", t)

    def test_repeal_note_kept(self):
        _, t = self.frag(LPI + "#art-40")
        self.assertIn("(Revogado pela Lei nº 14.195", t)

    def test_quote_contract_on_lpi(self):
        ok = donna.q_quote(self.con, LPI + "#art-158",
                           "podendo se manifestar no prazo de 60 (sessenta) dias")
        bad = donna.q_quote(self.con, LPI + "#art-158",
                            "podendo se manifestar no prazo de 30 (trinta) dias")
        self.assertTrue(ok["verified"])
        self.assertFalse(bad["verified"])

    def test_lpi_citation_forms(self):
        for c in ("art. 158, § 1º, da LPI", "art. 158 LPI",
                  "artigo 158 da Lei 9.279/96", "Art. 158 da Lei nº 9.279/1996"):
            self.assertEqual(donna.q_resolve(self.con, c)["id"], LPI + "#art-158", c)

    def test_manual_item_page_beats_chapter_toc(self):
        _, t = self.frag(MAN + "#sec-5.12")
        self.assertIn("instrumento de defesa do requerente", t)

    def test_manual_unnumbered_subheading_stays_inside_item(self):
        h, t = self.frag(MAN + "#sec-5.12.1")
        self.assertEqual(h, "Orientações gerais")
        self.assertIn("Exigências para a opoente", t)
        self.assertIn("A | B", t)

    def test_manual_citation_forms(self):
        for c in ("item 5.12.1 do Manual de Marcas", "Manual de Marcas 5.12.1",
                  "Manual de Marcas do INPI, item 5.12.1"):
            self.assertEqual(donna.q_resolve(self.con, c)["id"], MAN + "#sec-5.12.1", c)

    def test_manual_checks_recorded(self):
        import json
        row = self.con.execute("SELECT checks_json FROM attestations WHERE"
                               " expression_id = ?", (MAN,)).fetchone()
        checks = json.loads(row[0])
        self.assertEqual(checks["images_not_transcribed"], 1)
        self.assertEqual(checks["pages"], 2)

if __name__ == "__main__":
    unittest.main()
