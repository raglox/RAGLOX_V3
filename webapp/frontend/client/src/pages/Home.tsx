// RAGLOX v3.0 - Home Page
// Landing page with mission selection

import { useEffect, useState } from "react";
import { useLocation } from "wouter";
import { motion } from "framer-motion";
import { 
  Shield, 
  Target, 
  Zap, 
  ArrowRight,
  Plus,
  Clock,
  Activity
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { missionApi } from "@/lib/api";
import { cn } from "@/lib/utils";

// Demo Mission ID
const DEMO_MISSION_ID = "5bae06db-0f6c-478d-81a3-b54e2f3eb9d5";

export default function Home() {
  const [, setLocation] = useLocation();
  const [missions, setMissions] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    loadMissions();
  }, []);

  const loadMissions = async () => {
    try {
      const data = await missionApi.list();
      setMissions(data);
    } catch (error) {
      // API not available - use demo data silently
      console.log("API not available, using demo mode");
      // Set demo mission as fallback
      setMissions([DEMO_MISSION_ID]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleStartDemo = () => {
    setLocation(`/operations/${DEMO_MISSION_ID}`);
  };

  const handleGoToOperations = () => {
    setLocation("/operations");
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card">
        <div className="container flex items-center justify-between h-16">
          <div className="flex items-center gap-2">
            <Shield className="w-8 h-8 text-primary" />
            <span className="font-bold text-xl">RAGLOX</span>
            <span className="text-xs text-muted-foreground bg-muted px-2 py-0.5 rounded ml-2">
              v3.0
            </span>
          </div>
          <nav className="flex items-center gap-4">
            <Button variant="ghost" onClick={() => setLocation("/missions")}>
              Missions
            </Button>
            <Button variant="ghost" onClick={handleGoToOperations}>
              Operations
            </Button>
            <Button variant="ghost" onClick={() => setLocation("/knowledge")}>
              Knowledge
            </Button>
            <Button variant="default" onClick={handleStartDemo}>
              Start Demo
            </Button>
          </nav>
        </div>
      </header>

      {/* Hero Section */}
      <section className="py-20 px-4">
        <div className="container max-w-4xl text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            <h1 className="text-5xl font-bold mb-6">
              <span className="text-primary">AI-Powered</span> Security Operations
            </h1>
            <p className="text-xl text-muted-foreground mb-8 max-w-2xl mx-auto">
              RAGLOX is an autonomous penetration testing platform that combines 
              AI intelligence with human oversight for enterprise-grade security operations.
            </p>
            <div className="flex items-center justify-center gap-4">
              <Button size="lg" onClick={handleStartDemo} className="gap-2">
                <Zap className="w-5 h-5" />
                Start Demo Mission
              </Button>
              <Button size="lg" variant="outline" onClick={handleGoToOperations} className="gap-2">
                <ArrowRight className="w-5 h-5" />
                Go to Operations
              </Button>
            </div>
          </motion.div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-16 px-4 bg-muted/30">
        <div className="container">
          <h2 className="text-3xl font-bold text-center mb-12">
            Enterprise Security Platform
          </h2>
          <div className="grid md:grid-cols-3 gap-6">
            <FeatureCard
              icon={Target}
              title="Autonomous Recon"
              description="AI-driven reconnaissance that discovers targets, services, and vulnerabilities automatically."
            />
            <FeatureCard
              icon={Shield}
              title="Human-in-the-Loop"
              description="Critical actions require human approval, ensuring safe and controlled operations."
            />
            <FeatureCard
              icon={Activity}
              title="Real-time Monitoring"
              description="Live updates via WebSocket, terminal output, and comprehensive event logging."
            />
          </div>
        </div>
      </section>

      {/* Recent Missions */}
      <section className="py-16 px-4">
        <div className="container">
          <div className="flex items-center justify-between mb-8">
            <h2 className="text-2xl font-bold">Recent Missions</h2>
            <Button variant="outline" className="gap-2">
              <Plus className="w-4 h-4" />
              New Mission
            </Button>
          </div>

          {isLoading ? (
            <div className="flex items-center justify-center py-12">
              <div className="animate-spin w-8 h-8 border-2 border-primary border-t-transparent rounded-full" />
            </div>
          ) : missions.length > 0 ? (
            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4">
              {missions.slice(0, 6).map((missionId) => (
                <MissionCard
                  key={missionId}
                  missionId={missionId}
                  onClick={() => setLocation(`/operations/${missionId}`)}
                />
              ))}
            </div>
          ) : (
            <Card className="text-center py-12">
              <CardContent>
                <p className="text-muted-foreground mb-4">No missions found</p>
                <Button onClick={handleStartDemo}>Start Demo Mission</Button>
              </CardContent>
            </Card>
          )}
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border py-8">
        <div className="container text-center text-sm text-muted-foreground">
          <p>RAGLOX v3.0 - AI-Powered Security Operations Platform</p>
          <p className="mt-2">Built with React, TypeScript, and TailwindCSS</p>
        </div>
      </footer>
    </div>
  );
}

// Feature Card Component
interface FeatureCardProps {
  icon: React.ElementType;
  title: string;
  description: string;
}

function FeatureCard({ icon: Icon, title, description }: FeatureCardProps) {
  return (
    <Card className="bg-card hover:border-primary/50 transition-colors">
      <CardHeader>
        <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4">
          <Icon className="w-6 h-6 text-primary" />
        </div>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <CardDescription className="text-base">{description}</CardDescription>
      </CardContent>
    </Card>
  );
}

// Mission Card Component
interface MissionCardProps {
  missionId: string;
  onClick: () => void;
}

function MissionCard({ missionId, onClick }: MissionCardProps) {
  return (
    <Card 
      className="cursor-pointer hover:border-primary/50 transition-colors"
      onClick={onClick}
    >
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base font-medium truncate">
            Mission {missionId.slice(0, 8)}...
          </CardTitle>
          <span className="text-xs text-muted-foreground bg-muted px-2 py-0.5 rounded">
            Active
          </span>
        </div>
      </CardHeader>
      <CardContent>
        <div className="flex items-center gap-4 text-sm text-muted-foreground">
          <div className="flex items-center gap-1">
            <Target className="w-4 h-4" />
            <span>3 targets</span>
          </div>
          <div className="flex items-center gap-1">
            <Clock className="w-4 h-4" />
            <span>2h ago</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
