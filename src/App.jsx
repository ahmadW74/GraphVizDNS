import React, { useState } from "react";
import { RotateCcw, Search, User } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import { Slider } from "@/components/ui/slider";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import Graphviz from "graphviz-react";
import DNSSECVisualizer from "./DNSGraph.jsx";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
export default function App() {
  // UI state
  const [domain, setDomain] = useState("");
  const [currentDomain, setCurrentDomain] = useState("");
  const [refreshTrigger, setRefreshTrigger] = useState(0);
  const [inputDomain, setInputDomain] = useState("");
  const MAX_DAYS = 1825;
  const [timeline, setTimeline] = useState(MAX_DAYS);
  const [loginOpen, setLoginOpen] = useState(true);
  const [signupOpen, setSignupOpen] = useState(false);

  // Login state
  const [loginEmail, setLoginEmail] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [loginError, setLoginError] = useState("");
  const [username, setUsername] = useState("");

  // Signup state
  const [signupName, setSignupName] = useState("");
  const [signupEmail, setSignupEmail] = useState("");
  const [signupPassword, setSignupPassword] = useState("");
  const [signupMessage, setSignupMessage] = useState("");
  const [signupMessageType, setSignupMessageType] = useState(""); // "success" or "error"

  // Login handler
  const handleLogin = async () => {
    setLoginError("");
    try {
      const res = await fetch(
        `http://127.0.0.1:8000/login/${loginEmail}/${loginPassword}`
      );
      if (!res.ok) {
        setLoginError("Unable to verify credentials.");
        return;
      }
      const data = await res.json();
      const successVal = data.success.trim();
      if (successVal !== "no") {
        setUsername(successVal);
        setLoginError("");
        setLoginOpen(false);
      } else {
        setLoginError("Invalid email or password.");
      }
    } catch (err) {
      setLoginError("Error verifying credentials.");
    }
  };

  // Signup handler
  const handleSignup = async () => {
    setSignupMessage("");
    try {
      const res = await fetch(
        `http://127.0.0.1:8000/signup/${signupEmail}/${signupPassword}/${signupName}`
      );
      if (res.ok) {
        setSignupMessageType("success");
        setSignupMessage("Signup successful! Redirecting to login...");
        // After a brief pause, close signup and open login
        setTimeout(() => {
          setSignupOpen(false);
          setLoginOpen(true);
          setSignupMessage("");
        }, 1500);
      } else {
        setSignupMessageType("error");
        setSignupMessage("Signup failed. Please try again.");
      }
    } catch (err) {
      setSignupMessageType("error");
      setSignupMessage("Error during signup. Please try later.");
    }
  };

  // Data fetching logic
  const handleAnalyze = () => {
    if (domain.trim()) {
      setCurrentDomain(domain.trim());
    }
  };

  const handleRefresh = () => {
    if (currentDomain) {
      setRefreshTrigger((prev) => prev + 1);
    }
  };

  // Graphviz DOT string for DNS chain visualization
  const dotString = `
    digraph G {
      node [shape=box style=filled];
      // Root DNSKEYs
      root0 [label="root DNSKEY 0" fillcolor=green];
      root1 [label="root DNSKEY 1" fillcolor=green];
      root2 [label="root DNSKEY 2" fillcolor=white];

      // .com chain
      com_ds [label="com DS" fillcolor=green];
      com_dnskey0 [label="com DNSKEY 0" fillcolor=green];
      com_dnskey1 [label="com DNSKEY 1" fillcolor=green];

      // google.com and mail.google.com
      google [label="google.com" fillcolor=white];
      mail [label="mail.google.com" fillcolor=white];

      // Edges
      root0 -> root1;
      root0 -> root2;
      root1 -> com_ds;
      com_ds -> com_dnskey0;
      com_dnskey0 -> com_dnskey1;
      com_dnskey1 -> google [color=red];
      google -> mail;
    }
  `;

  // Slider tooltip label
  const selectedDate = new Date();
  selectedDate.setDate(selectedDate.getDate() - (MAX_DAYS - timeline));
  const tooltipLabel =
    timeline === MAX_DAYS ? "Today" : selectedDate.toLocaleDateString();

  return (
    <div className="dark bg-neutral-950 text-neutral-100 min-h-screen flex flex-col text-base lg:text-lg">
      {/* Login dialog */}
      <Dialog open={loginOpen} onOpenChange={setLoginOpen}>
        <DialogContent className="sm:max-w-lg text-base space-y-6">
          <DialogHeader>
            <DialogTitle className="text-2xl">Log in</DialogTitle>
            <DialogDescription className="text-neutral-400">
              Enter your account credentials to continue.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            {loginError && (
              <div className="bg-red-600 text-white p-2 rounded">
                {loginError}
              </div>
            )}
            <Input
              placeholder="Email"
              type="email"
              className="h-12 text-lg"
              value={loginEmail}
              onChange={(e) => setLoginEmail(e.target.value)}
            />
            <Input
              placeholder="Password"
              type="password"
              className="h-12 text-lg"
              value={loginPassword}
              onChange={(e) => setLoginPassword(e.target.value)}
            />
            <Button className="w-full h-12 text-lg" onClick={handleLogin}>
              Log in
            </Button>
            <p className="text-sm text-center text-neutral-400">
              Don't have an account?{" "}
              <button
                className="text-blue-400 hover:underline"
                onClick={() => {
                  setLoginOpen(false);
                  setSignupOpen(true);
                }}
              >
                Sign up
              </button>
            </p>
          </div>
        </DialogContent>
      </Dialog>

      {/* Signup dialog */}
      <Dialog open={signupOpen} onOpenChange={setSignupOpen}>
        <DialogContent className="sm:max-w-lg text-base space-y-6">
          <DialogHeader>
            <DialogTitle className="text-2xl">Sign up</DialogTitle>
            <DialogDescription className="text-neutral-400">
              Create a new account to get started.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            {signupMessage && (
              <div
                className={`${
                  signupMessageType === "success"
                    ? "bg-green-600"
                    : "bg-red-600"
                } text-white p-2 rounded`}
              >
                {signupMessage}
              </div>
            )}
            <Input
              placeholder="Name"
              className="h-12 text-lg"
              value={signupName}
              onChange={(e) => setSignupName(e.target.value)}
            />
            <Input
              placeholder="Email"
              type="email"
              className="h-12 text-lg"
              value={signupEmail}
              onChange={(e) => setSignupEmail(e.target.value)}
            />
            <Input
              placeholder="Password"
              type="password"
              className="h-12 text-lg"
              value={signupPassword}
              onChange={(e) => setSignupPassword(e.target.value)}
            />
            <Button className="w-full h-12 text-lg" onClick={handleSignup}>
              Sign up
            </Button>
            <p className="text-sm text-center text-neutral-400">
              Already have an account?{" "}
              <button
                className="text-blue-400 hover:underline"
                onClick={() => {
                  setSignupOpen(false);
                  setLoginOpen(true);
                }}
              >
                Log in
              </button>
            </p>
          </div>
        </DialogContent>
      </Dialog>

      {/* Header */}
      <header className="border-b border-neutral-800">
        <div className="mx-auto max-w-7xl p-6 flex justify-between items-center">
          <h1 className="text-3xl font-semibold tracking-tight">
            DNS Chain Visualizer
          </h1>
          <div className="flex items-center space-x-2">
            <User className="h-6 w-6 text-neutral-100" />
            <span className="text-lg">{username}</span>
          </div>
        </div>
      </header>

      {/* Main content */}
      <main className="flex-grow flex items-start justify-center p-6 lg:p-10">
        <div className="w-full max-w-6xl space-y-6 lg:space-y-8">
          {/* Search bar */}
          <div className="flex justify-center mb-4 lg:mb-6">
            <Input
              placeholder="example.com"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              className="w-80 h-12 lg:h-14 text-lg rounded-l-full rounded-r-none shadow-inner"
            />
            <Button
              size="icon"
              variant="secondary"
              onClick={handleAnalyze}
              disabled={!domain.trim()}
              className="rounded-r-full rounded-l-none border-l-0 h-12 lg:h-14"
            >
              <Search className="h-6 w-6" />
            </Button>
          </div>

          {/* Timeline slider */}
          <div className="relative mb-6 h-6 lg:h-8">
            <div className="absolute -top-10 left-0 w-full pointer-events-none">
              <div
                style={{ left: `${(timeline / MAX_DAYS) * 100}%` }}
                className="absolute transform -translate-x-1/2 bg-neutral-800 text-neutral-100 text-sm lg:text-base px-3 py-2 rounded shadow"
              >
                {tooltipLabel}
              </div>
            </div>
            <Slider
              min={0}
              max={MAX_DAYS}
              step={1}
              value={[timeline]}
              onValueChange={(v) => setTimeline(v[0])}
              className="h-full"
            />
          </div>
          {/* Graphviz rendering card */}
          <div className="relative">
            <Card className="w-full bg-neutral-900 border-neutral-800">
              {/* Make the inner area relative so we can absolutely position the tab buttons */}
              <CardContent className="relative px-10 py-10 lg:px-14 lg:py-14">
                {/* Give Tabs the full available space */}
                <Tabs defaultValue="Non-GraphViz" className="w-full h-full">
                  {/* ---- Tab selector (now top-left) ---- */}
                  <TabsList className="absolute top-4 left-4 flex gap-2">
                    <TabsTrigger value="Non-GraphViz">Non-GraphViz</TabsTrigger>
                    <TabsTrigger value="GraphViz">GraphViz</TabsTrigger>
                  </TabsList>

                  {/* ---- Non-GraphViz panel ---- */}
                  <TabsContent
                    value="Non-GraphViz"
                    className="w-full min-h-[450px] pt-14" /* pt-14 pushes content below the buttons */
                  >
                    <DNSSECVisualizer
                      domain={currentDomain}
                      refreshTrigger={refreshTrigger}
                    />
                  </TabsContent>

                  {/* ---- GraphViz panel ---- */}
                  <TabsContent
                    value="GraphViz"
                    className="w-full min-h-[450px] pt-14"
                  >
                    <Graphviz
                      dot={dotString}
                      options={{ engine: "dot" }}
                      style={{ width: "100%" }} /* prevents horizontal shrink */
                    />
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>

            {/* Reload button (unchanged) */}
            <Button
              size="icon"
              variant="secondary"
              onClick={handleRefresh}
              disabled={!currentDomain}
              className="absolute -right-16 top-4 h-12 w-12"
            >
              <RotateCcw className="h-6 w-6" />
            </Button>
          </div>
        </div>
      </main>
    </div>
  );
}
