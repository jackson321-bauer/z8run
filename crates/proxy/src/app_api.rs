//! App- und LLM-API: Apps sehen NIE Prompts; LLM-Antworten werden von
//! Prompt-Inhalt befreit, bevor sie den Aufrufer erreichen.

use proxy_kern::{AppCallResult, AppInfo, ProxyError};
use serde_json::Value;

use crate::apps::redact_value;
use crate::service::ProxyService;

impl ProxyService {
    pub fn app_list(&self, token: &str) -> Result<Vec<AppInfo>, ProxyError> {
        self.authenticate(token)?;
        Ok(self.apps.list())
    }

    pub fn app_call(
        &self,
        token: &str,
        app_name: &str,
        input: &Value,
    ) -> Result<AppCallResult, ProxyError> {
        let info = self.authenticate(token)?;
        let app = self.apps.get(app_name)?;
        let reply = app.handle(input)?;
        let name = app.name().to_string();
        self.sessions.with(&info.session_id, |s| s.add_app(&name));
        Ok(AppCallResult {
            app: name,
            payload: reply.payload,
            stream_len: reply.stream.as_ref().map(|b| b.len()),
        })
    }

    pub async fn llm_call(
        &self,
        token: &str,
        prompt_name: &str,
        user_msg: &str,
    ) -> Result<Value, ProxyError> {
        self.authenticate(token)?;
        let system = self.prompts.get(prompt_name)?;
        let text = core::str::from_utf8(&system)
            .map_err(|e| ProxyError::Internal(format!("Prompt kein UTF-8: {e}")))?;
        let mut out = self.llm.complete(text, user_msg).await?;
        redact_value(&mut out, text);
        Ok(out)
    }
}
