require ["variables", "spamtest", "spamtestplus", "reject"];

set "level" "none";
set "percent" "none";

if spamtest :matches "*" {
	set "level" "${0}";
}

if spamtest :percent :matches "*" {
	set "percent" "${0}";
}

reject "spamtest=${level} percent=${percent} score=${env.spam.score} is_spam=${env.spam.is_spam}";
