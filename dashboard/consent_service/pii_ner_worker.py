"""Local NER worker for PII detection v2: run by pii_engine.NER with consent_service/.pii-venv/bin/python.

Reads one JSON line per request, {"texts": [...]}, and answers one JSON line, {"results": [[{type, start,
end, score}, …], …]}, with PERSON and LOCATION entities from Microsoft Presidio on spaCy's
en_core_web_lg model. Nothing is written to disk, nothing leaves the machine.
"""
import json
import sys


def main():
    try:
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider
        model = "en_core_web_lg"
        nlp = NlpEngineProvider(nlp_configuration={"nlp_engine_name": "spacy", "models": [{"lang_code": "en", "model_name": model}]}).create_engine()
        engine = AnalyzerEngine(nlp_engine=nlp, supported_languages=["en"])
        engine.analyze(text="Warm-up for Ramesh Kumar in Pune", language="en", entities=["PERSON", "LOCATION"])
    except Exception as e:  # missing packages or model: tell the parent and stop
        print(json.dumps({"ready": False, "error": f"{type(e).__name__}: {e}"[:300]}), flush=True)
        return
    print(json.dumps({"ready": True, "model": f"presidio + spaCy {model}"}), flush=True)
    for line in sys.stdin:
        try:
            req = json.loads(line)
            results = []
            for t in req.get("texts", []):
                ents = engine.analyze(text=str(t), language="en", entities=["PERSON", "LOCATION"]) if t else []
                results.append([{"type": e.entity_type, "start": e.start, "end": e.end, "score": round(e.score, 3)} for e in ents])
            print(json.dumps({"results": results}), flush=True)
        except Exception as e:
            print(json.dumps({"results": [], "error": f"{type(e).__name__}: {e}"[:300]}), flush=True)


if __name__ == "__main__":
    main()
