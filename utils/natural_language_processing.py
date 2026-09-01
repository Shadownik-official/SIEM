import spacy
from spacy.pipeline import EntityRuler
from spacy.language import Language

nlp = spacy.load("en_core_web_sm")
nlp.add_pipe("entity_ruler", before="ner")
nlp.remove_pipe("entity_ruler")
import logging

# Set up logging
logging.basicConfig(filename="nlp.log", level=logging.INFO)

nlp = spacy.load("en_core_web_sm")
nlp.add_pipe("entity_ruler", before="ner")
nlp.remove_pipe("entity_ruler")
# Define constants for entity labels and patterns
ENTITY_LABELS = ["THREAT", "ATTACK_VECTOR", "SEVERITY"]
THREAT_PATTERNS = [
    "Denial of Service",
    "SQL Injection",
    "Cross-Site Scripting",
    "Malware",
    "Phishing",
    "Ransomware",
    "Man in the Middle",
    "Zero Day Exploit",
]
ATTACK_VECTOR_PATTERNS = [
    "Port Scan",
    "Brute Force",
    "Session Hijacking",
]
SEVERITY_PATTERNS = [
    "Critical",
    "High",
    "Medium",
    "Low",
    "Informational",
]

nlp = spacy.load("en_core_web_sm")

@Language.component("custom_entity_ruler")
class CustomEntityRuler(EntityRuler):
    def __init__(self, vocab):
        super().__init__(vocab)
        self.patterns = [
            {"label": label, "pattern": pattern}
            for label, patterns in zip(ENTITY_LABELS, [THREAT_PATTERNS, ATTACK_VECTOR_PATTERNS, SEVERITY_PATTERNS])
            for pattern in patterns
        ]

    def __call__(self, doc):
        return self.add_patterns(doc, self.patterns)

nlp.add_pipe("custom_entity_ruler", before="ner")
nlp.remove_pipe("entity_ruler")

def process_log_message(log_message: str) -> spacy.tokens.doc.Doc:
    """
    Process a log message using spaCy NLP pipeline.

    Parameters:
    log_message (str): The log message to process.

    Returns:
    spacy.tokens.doc.Doc: The processed log message with annotations.

    Raises:
    ValueError: If the `nlp` object is not initialized.
    """
    if not nlp:
        raise ValueError("spaCy model is not initialized")
    return nlp(log_message)

def extract_entities(doc: spacy.tokens.doc.Doc) -> list[tuple[str, str]]:
    """
    Extract entities from a processed log message.

    Parameters:
    doc (spacy.tokens.doc.Doc): The processed log message.

    Returns:
    list[tuple[str, str]]: A list of tuples with entity text and label.
    """
    return [(ent.text, ent.label_) for ent in doc.ents]

def classify_intent(doc: spacy.tokens.doc.Doc) -> str:
    """
    Classify the intent of the log message based on the entities present.

    Parameters:
    doc (spacy.tokens.doc.Doc): The processed log message.

    Returns:
    str: The classified intent.
    """
    intent_map = {
        "THREAT": "Threat Detected",
        "ATTACK_VECTOR": "Attack Vector Identified",
        "SEVERITY": "Severity Level Reported"
    }
    for ent in doc.ents:
        if ent.label_ in intent_map:
            return intent_map[ent.label_]
    return "General Information"