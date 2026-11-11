# Demo: 3-minute narration script

**Video:** [demo/log-analyzer-demo.mp4](demo/log-analyzer-demo.mp4) (3:04, 1280×720, captions burnt in, no audio track).
Rebuild it after any change with `PYTHONPATH=src python3 docs/demo/make_video.py`; every scene is drawn from the project's real outputs and `evals/results/`.

**To add your voice:** read each block at a relaxed pace (about 150 words a minute; each block fits its scene). Record it as one file, then:

```bash
ffmpeg -i docs/demo/log-analyzer-demo.mp4 -i voice.m4a -map 0:v -map 1:a -c:v copy -c:a aac -shortest docs/demo/log-analyzer-demo-voice.mp4
```

---

**0:00-0:10 · Title**
> This is log-analyzer. Point it at a messy log and it tells you what broke, how often, when it spiked, and what it couldn't read.

**0:10-0:28 · Real logs fight back**
> The demo generates ten thousand log entries and makes them realistically messy: lines cut off mid-write, a wrong date format, month thirteen, JSON from another service, glued lines, and stack traces. A good analyzer survives all of it.

**0:28-0:46 · How it works**
> It's one pass through the file. The reader opens it in binary and caps each line at eight kilobytes. Regular expressions sort every line into an entry, a stack trace, a blank, or malformed with a reason. Then errors are grouped, spikes found, and reports written, in flat memory.

**0:46-1:06 · make demo**
> Here it is running: ten and a half thousand lines in eight hundredths of a second. Four hundred and eighty-one errors in thirteen groups, and three spikes, exactly the three the generator planted, each blamed on the right error.

**1:06-1:22 · The HTML report**
> The HTML report has the headline numbers and errors over six hours. The pale red bands are the detected spikes. The same data comes out as Markdown for GitHub or Slack, and JSON for other tools.

**1:22-1:38 · Spikes and causes**
> Spikes are judged against traffic, not raw counts. Three times the requests means three times the errors at the same failure rate: busy, not broken. So it asks what a normal minute with this traffic would have.

**1:38-1:54 · Malformed lines**
> The bonus: malformed logs. A hundred and fifty-three lines are labelled with a reason and quarantined. JSON and glued lines are recovered, stack traces attached. One bad line never stops the run.

**1:54-2:16 · Hard numbers**
> Every claim is measured against an answer key. One hundred percent line classification on held-out files, thirty-nine of forty hand-written tricky lines, all one hundred and fifty planted spikes found, none falsely raised by traffic surges. Seventy-five milliseconds, zero cost, and zero of thirty-two attacks succeed.

**2:16-2:32 · Each defence switched off**
> Anyone who types into a form writes to your logs. Zero percent attack success could just mean weak attacks, so each defence is switched off in turn, and its attacks then get through: forged lines, giant lines, the year 9999, script injection.

**2:32-2:52 · Postmortem**
> Each problem was found by a number that looked off. A regex missed numbers glued to units, so one error became dozens of groups. An e-mail pattern took twelve seconds on one hostile line; now a millisecond. And two checks could never fail, until I tested them.

**2:52-3:04 · Next**
> Next: a week of real logs, learning variable words from the data, and more formats. The design doc, postmortem and cheatsheet are in the repo.
