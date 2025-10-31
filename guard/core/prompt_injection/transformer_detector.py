# guard/core/prompt_injection/transformer_detector.py
import logging
from typing import Any

logger = logging.getLogger(__name__)


class TransformerDetector:
    """
    High-accuracy detection using transformer models.

    Uses pre-trained DeBERTa models from ProtectAI/HuggingFace
    that achieve 99%+ accuracy on prompt injection detection.
    """

    def __init__(
        self,
        model_name: str = "protectai/deberta-v3-base-prompt-injection",
        confidence_threshold: float = 0.5,
        cache_predictions: bool = True,
    ) -> None:
        """
        Initialize the transformer detector.

        Args:
            model_name: HuggingFace model name for detection.
                Options:
                - protectai/deberta-v3-base-prompt-injection (99.99% accuracy)
                - deepset/deberta-v3-base-injection (99.1% accuracy)
            confidence_threshold: Confidence threshold (0.0-1.0).
                Higher = more strict. Default 0.5 = balanced.
            cache_predictions: Whether to cache predictions.
        """
        self.model_name = model_name
        self.confidence_threshold = confidence_threshold
        self.cache_predictions = cache_predictions

        # Lazy load model (only when first used)
        self._model: Any = None
        self._tokenizer: Any = None
        self._prediction_cache: dict[str, dict[str, Any]] = {}

        logger.info(
            f"TransformerDetector initialized with model={model_name}, "
            f"threshold={confidence_threshold}"
        )

    def _load_model(self) -> None:
        """Load the transformer model and tokenizer lazily."""
        if self._model is not None:
            return

        try:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            logger.info(f"Loading transformer model: {self.model_name}")

            self._tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self._model = AutoModelForSequenceClassification.from_pretrained(
                self.model_name
            )

            # Move to GPU if available
            try:
                import torch

                if torch.cuda.is_available():
                    self._model = self._model.cuda()
                    logger.info("Model moved to GPU")
            except ImportError:
                pass

            logger.info("Model loaded successfully")

        except ImportError as e:
            logger.error(
                "transformers not installed. "
                "Install with: pip install transformers torch"
            )
            raise ImportError(
                "TransformerDetector requires transformers. "
                "Install with: pip install transformers torch"
            ) from e
        except Exception as e:
            logger.error(f"Failed to load model {self.model_name}: {e}")
            raise

    def _predict(self, text: str) -> dict[str, Any]:
        """
        Run model prediction on text.

        Args:
            text: Input text to analyze.

        Returns:
            Prediction dictionary with scores and labels.
        """
        # Check cache first
        if self.cache_predictions and text in self._prediction_cache:
            return self._prediction_cache[text]

        # Ensure model is loaded
        self._load_model()

        try:
            import torch

            # Tokenize input
            inputs = self._tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=True,
            )

            # Move to GPU if model is on GPU
            if next(self._model.parameters()).is_cuda:
                inputs = {k: v.cuda() for k, v in inputs.items()}

            # Run inference
            with torch.no_grad():
                outputs = self._model(**inputs)
                logits = outputs.logits
                probabilities = torch.softmax(logits, dim=-1)

            # Get predictions
            predicted_class = torch.argmax(probabilities, dim=-1).item()
            confidence = probabilities[0][predicted_class].item()

            # Map class to label (0 = benign, 1 = injection)
            is_injection = predicted_class == 1
            injection_confidence = probabilities[0][1].item()
            benign_confidence = probabilities[0][0].item()

            result = {
                "is_injection": bool(is_injection),
                "confidence": float(confidence),
                "injection_score": float(injection_confidence),
                "benign_score": float(benign_confidence),
                "predicted_class": int(predicted_class),
            }

            # Cache if enabled
            if self.cache_predictions:
                self._prediction_cache[text] = result

            return result

        except Exception as e:
            logger.error(f"Error during prediction: {e}")
            raise

    def is_suspicious(self, text: str) -> bool:
        """
        Check if text is a prompt injection attempt.

        Args:
            text: Input text to analyze.

        Returns:
            True if injection detected, False otherwise.
        """
        try:
            prediction = self._predict(text)

            is_suspicious = (
                prediction["is_injection"]
                and prediction["injection_score"] >= self.confidence_threshold
            )

            if is_suspicious:
                logger.warning(
                    f"Injection detected (confidence: "
                    f"{prediction['injection_score']:.3f})"
                )

            return is_suspicious

        except Exception as e:
            logger.error(f"Error in transformer detection: {e}")
            # Fail open: don't block on errors
            return False

    def get_prediction(self, text: str) -> dict[str, Any]:
        """
        Get detailed prediction analysis.

        Args:
            text: Input text to analyze.

        Returns:
            Dictionary with prediction details.
        """
        try:
            prediction = self._predict(text)

            prediction["is_suspicious"] = (
                prediction["is_injection"]
                and prediction["injection_score"] >= self.confidence_threshold
            )
            prediction["threshold"] = self.confidence_threshold
            prediction["model_name"] = self.model_name

            return prediction

        except Exception as e:
            logger.error(f"Error getting prediction: {e}")
            return {
                "is_suspicious": False,
                "is_injection": False,
                "confidence": 0.0,
                "injection_score": 0.0,
                "benign_score": 0.0,
                "threshold": self.confidence_threshold,
                "error": str(e),
            }

    def batch_predict(self, texts: list[str]) -> list[dict[str, Any]]:
        """
        Run predictions on multiple texts efficiently.

        Args:
            texts: List of texts to analyze.

        Returns:
            List of prediction dictionaries.
        """
        self._load_model()

        try:
            import torch

            # Tokenize all inputs
            inputs = self._tokenizer(
                texts,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=True,
            )

            # Move to GPU if model is on GPU
            if next(self._model.parameters()).is_cuda:
                inputs = {k: v.cuda() for k, v in inputs.items()}

            # Run batch inference
            with torch.no_grad():
                outputs = self._model(**inputs)
                logits = outputs.logits
                probabilities = torch.softmax(logits, dim=-1)

            # Parse results
            results = []
            for i in range(len(texts)):
                predicted_class = torch.argmax(probabilities[i]).item()
                confidence = probabilities[i][predicted_class].item()

                is_injection = predicted_class == 1
                injection_confidence = probabilities[i][1].item()
                benign_confidence = probabilities[i][0].item()

                results.append(
                    {
                        "is_injection": bool(is_injection),
                        "confidence": float(confidence),
                        "injection_score": float(injection_confidence),
                        "benign_score": float(benign_confidence),
                        "predicted_class": int(predicted_class),
                        "is_suspicious": is_injection
                        and injection_confidence >= self.confidence_threshold,
                    }
                )

            return results

        except Exception as e:
            logger.error(f"Error in batch prediction: {e}")
            return [{"is_suspicious": False, "error": str(e)} for _ in texts]

    def clear_cache(self) -> None:
        """Clear the prediction cache."""
        self._prediction_cache.clear()
        logger.info("Prediction cache cleared")

    def get_stats(self) -> dict[str, Any]:
        """
        Get detector statistics.

        Returns:
            Dictionary with detector stats.
        """
        is_cuda = False
        if self._model is not None:
            try:
                is_cuda = next(self._model.parameters()).is_cuda
            except Exception:
                pass

        return {
            "model_name": self.model_name,
            "model_loaded": self._model is not None,
            "confidence_threshold": self.confidence_threshold,
            "cache_size": len(self._prediction_cache),
            "cache_enabled": self.cache_predictions,
            "using_gpu": is_cuda,
        }
