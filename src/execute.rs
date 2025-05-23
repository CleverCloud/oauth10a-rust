/// Execute HTTP requests.
pub trait Execute {
    type Error;

    fn execute(
        &self,
        request: reqwest::Request,
    ) -> impl Future<Output = Result<reqwest::Response, Self::Error>> + Send + 'static;
}

impl Execute for reqwest::Client {
    type Error = reqwest::Error;

    #[inline]
    fn execute(
        &self,
        request: reqwest::Request,
    ) -> impl Future<Output = Result<reqwest::Response, Self::Error>> + Send + 'static {
        self.execute(request)
    }
}
