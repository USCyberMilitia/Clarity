# Clarity
Clarity: Evidence and Case Analysis Workstation
<img width="2559" height="1526" alt="image" src="https://github.com/user-attachments/assets/b2a5209c-87cd-4c97-b1b2-6441f52b8444" />
# Install Clarity

**Clarity: Evidence and Case Analysis Workstation** is a desktop tool for reviewing bodycam footage, audio, video, transcripts, documents, reports, speaker diarization, force-moment timelines, inconsistencies, and case evidence.

Clarity can work with:

- video files
- audio files
- images
- PDFs
- DOCX / RTF / TXT / CSV / JSON / LOG files
- SRT / VTT transcripts
- sidecar transcript files
- sidecar RTTM speaker diarization files
- optional Whisper transcription
- optional pyannote.audio speaker diarization

---

# Requirements

Clarity requires:

- **Python 3.10+**
- **Tkinter** for the desktop GUI
- **FFmpeg + FFprobe** for media metadata and audio extraction
- **Whisper / Faster-Whisper** for optional transcription
- **Torch** for Whisper / pyannote workflows
- **Optional document/OCR packages** for PDFs/images
- **Optional pyannote.audio + Hugging Face token** for real speaker diarization

You do **not** need to create a `requirements.txt` file. The full `pip install` command is included below.

---

# Windows Install

These instructions are for Windows 10 / Windows 11.

## 1. Install Git, Python, FFmpeg, and Tesseract OCR

Open **PowerShell as Administrator** and run:

```powershell
winget install --id Git.Git -e
winget install --id Python.Python.3.11 -e
winget install --id Gyan.FFmpeg -e
winget install --id UB-Mannheim.TesseractOCR -e
```

Close PowerShell, reopen it, then verify everything installed correctly:

```powershell
git --version
python --version
ffmpeg -version
ffprobe -version
tesseract --version
```

If `ffmpeg`, `ffprobe`, or `tesseract` is not found, restart PowerShell or reboot Windows.

---

## 2. Clone Clarity

```powershell
git clone https://github.com/USCyberMilitia/Clarity.git
cd Clarity
```

---

## 3. Create a virtual environment

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
```

---

## 4. Install all Python dependencies

Run this after activating the virtual environment:

```powershell
pip install faster-whisper openai-whisper torch torchvision torchaudio pypdf PyPDF2 pdfminer.six pillow pytesseract pyannote.audio torchcodec
```

This installs:

- Faster-Whisper
- OpenAI Whisper
- Torch / TorchVision / TorchAudio
- PDF extraction libraries
- image/OCR helper libraries
- pyannote.audio speaker diarization support
- torchcodec support

---

## 5. Optional NVIDIA GPU PyTorch install

If you have an NVIDIA GPU and want GPU acceleration, install the CUDA-enabled PyTorch build that matches your system.

Example CUDA 12.1 install:

```powershell
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121
pip install faster-whisper openai-whisper pypdf PyPDF2 pdfminer.six pillow pytesseract pyannote.audio torchcodec
```

If CUDA 12.1 is not right for your machine, use the official PyTorch install selector:

```text
https://pytorch.org/get-started/locally/
```

---

## 6. Optional Hugging Face token for pyannote speaker diarization

Real speaker diarization through `pyannote.audio` may require a Hugging Face token.

Set your token in PowerShell:

```powershell
setx HF_TOKEN "PASTE_YOUR_HUGGING_FACE_TOKEN_HERE"
```

Then close and reopen PowerShell.

Some pyannote models may also require accepting model terms on Hugging Face before they can be used.

---

## 7. Run Clarity

```powershell
python Clarity.py
```

---

## 8. Run dependency check

```powershell
python Clarity.py --dependency-check
```

---

## 9. Run self-test

```powershell
python Clarity.py --self-test
```

---

# Linux Install

These commands are for Debian, Ubuntu, Linux Mint, and similar distributions.

## 1. Install system dependencies

```bash
sudo apt update
sudo apt install -y git python3 python3-pip python3-venv python3-tk ffmpeg tesseract-ocr libgl1 libglib2.0-0
```

Verify everything installed correctly:

```bash
git --version
python3 --version
ffmpeg -version
ffprobe -version
tesseract --version
```

---

## 2. Clone Clarity

```bash
git clone https://github.com/USCyberMilitia/Clarity.git
cd Clarity
```

---

## 3. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
```

---

## 4. Install all Python dependencies

Run this after activating the virtual environment:

```bash
pip install faster-whisper openai-whisper torch torchvision torchaudio pypdf PyPDF2 pdfminer.six pillow pytesseract pyannote.audio torchcodec
```

This installs:

- Faster-Whisper
- OpenAI Whisper
- Torch / TorchVision / TorchAudio
- PDF extraction libraries
- image/OCR helper libraries
- pyannote.audio speaker diarization support
- torchcodec support

---

## 5. Optional NVIDIA GPU PyTorch install

If you have an NVIDIA GPU and want GPU acceleration, install the CUDA-enabled PyTorch build that matches your system.

Example CUDA 12.1 install:

```bash
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121
pip install faster-whisper openai-whisper pypdf PyPDF2 pdfminer.six pillow pytesseract pyannote.audio torchcodec
```

If CUDA 12.1 is not right for your machine, use the official PyTorch install selector:

```text
https://pytorch.org/get-started/locally/
```

---

## 6. Optional Hugging Face token for pyannote speaker diarization

Real speaker diarization through `pyannote.audio` may require a Hugging Face token.

Set your token:

```bash
export HF_TOKEN="PASTE_YOUR_HUGGING_FACE_TOKEN_HERE"
```

To make it persistent, add it to your shell profile:

```bash
echo 'export HF_TOKEN="PASTE_YOUR_HUGGING_FACE_TOKEN_HERE"' >> ~/.bashrc
source ~/.bashrc
```

Some pyannote models may also require accepting model terms on Hugging Face before they can be used.

---

## 7. Run Clarity

```bash
python Clarity.py
```

If your system requires `python3` instead:

```bash
python3 Clarity.py
```

---

## 8. Run dependency check

```bash
python Clarity.py --dependency-check
```

or:

```bash
python3 Clarity.py --dependency-check
```

---

## 9. Run self-test

```bash
python Clarity.py --self-test
```

or:

```bash
python3 Clarity.py --self-test
```

# Troubleshooting

## FFmpeg or FFprobe not found

Clarity needs both `ffmpeg` and `ffprobe`.

Check:

```bash
ffmpeg -version
ffprobe -version
```

If either command fails, FFmpeg is not installed correctly or is not on PATH.

On Windows, restart PowerShell or reboot after installing FFmpeg.

---

## Tesseract not found

Check:

```bash
tesseract --version
```

If it fails, install Tesseract.

Windows:

```powershell
winget install --id UB-Mannheim.TesseractOCR -e
```

Linux:

```bash
sudo apt install -y tesseract-ocr
```

---

## Tkinter missing on Linux

If the GUI does not open and Python reports that `tkinter` is missing, install:

```bash
sudo apt install -y python3-tk
```

Then try again:

```bash
python3 Clarity.py
```

---

## Whisper is slow

Use a smaller model first, such as:

```text
tiny
base
small
```

The default tiny model is fastest.

If you have an NVIDIA GPU, install the correct CUDA-enabled PyTorch build from:

```text
https://pytorch.org/get-started/locally/
```

---

## Faster-Whisper fails

Try updating it:

```bash
pip install -U faster-whisper
```

If Faster-Whisper does not work on your machine, try OpenAI Whisper instead:

```bash
pip install -U openai-whisper torch
```

---

## OpenAI Whisper wrong package error

If Clarity says a module named `whisper` is installed but it is not OpenAI Whisper, run:

```bash
pip uninstall -y whisper
pip install -U openai-whisper
```

---

## pyannote speaker diarization does not work

Make sure you installed:

```bash
pip install pyannote.audio torchcodec
```

Then make sure your Hugging Face token is set.

Windows PowerShell:

```powershell
setx HF_TOKEN "PASTE_YOUR_HUGGING_FACE_TOKEN_HERE"
```

Linux:

```bash
export HF_TOKEN="PASTE_YOUR_HUGGING_FACE_TOKEN_HERE"
```

Some pyannote models may also require accepting model terms on Hugging Face before they can be used.

---

## Torch / CUDA problems

If GPU mode fails, switch Clarity settings back to CPU.

Recommended safe defaults:

```text
whisper_device = cpu
whisper_compute_type = int8
whisper_model = tiny
whisper_beam_size = 1
```

Then test again.

---

## Run after reopening your terminal

Every time you reopen a terminal, activate the virtual environment first.

Windows:

```powershell
.\.venv\Scripts\Activate.ps1
python Clarity.py
```

Linux:

```bash
source .venv/bin/activate
python Clarity.py
```

---

# Quick Install Summary

## Windows Quick Install

```powershell
winget install --id Git.Git -e
winget install --id Python.Python.3.11 -e
winget install --id Gyan.FFmpeg -e
winget install --id UB-Mannheim.TesseractOCR -e

git clone https://github.com/USCyberMilitia/Clarity.git
cd Clarity

py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel

pip install faster-whisper openai-whisper torch torchvision torchaudio pypdf PyPDF2 pdfminer.six pillow pytesseract pyannote.audio torchcodec

python Clarity.py --dependency-check
python Clarity.py --self-test
python Clarity.py
```

---

## Linux Quick Install

```bash
sudo apt update
sudo apt install -y git python3 python3-pip python3-venv python3-tk ffmpeg tesseract-ocr libgl1 libglib2.0-0

git clone https://github.com/USCyberMilitia/Clarity.git
cd Clarity

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel

pip install faster-whisper openai-whisper torch torchvision torchaudio pypdf PyPDF2 pdfminer.six pillow pytesseract pyannote.audio torchcodec

python Clarity.py --dependency-check
python Clarity.py --self-test
python Clarity.py
```

---

# Recommended First Test

After installing, run:

```bash
python Clarity.py --dependency-check
```

Then run:

```bash
python Clarity.py --self-test
```

Then launch the app:

```bash
python Clarity.py
```
